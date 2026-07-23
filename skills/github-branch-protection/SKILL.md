---
name: github-branch-protection
description: Configura protecao de branch main no GitHub. Detecta plano (free vs pago), usa branch protection nativa (Team/Pro) ou workaround via GitHub Actions (free). Testa o fluxo de ponta a ponta e limpa artefatos de teste.
tags:
  - github
  - branch-protection
  - ci
  - devops
  - security
---

# GitHub Branch Protection Skill

Protege a branch `main` (ou qualquer branch alvo) contra push direto. Toda alteracao deve passar por PR.

## Quando usar

- `/github-branch-protection` — detecta repo atual e configura
- `/github-branch-protection <branch>` — protege branch especifica (default: `main`)
- `/github-branch-protection status` — verifica se protecao esta ativa
- `/github-branch-protection remove` — remove protecao

---

## Fluxo de execucao

### 1. Detectar repositorio e plano

```bash
# Obter owner/repo do remote atual
REPO=$(git remote get-url origin | sed 's/.*github\.com[:/]\(.*\)\.git/\1/' | sed 's/.*github\.com[:/]\(.*\)/\1/')
OWNER=$(echo "$REPO" | cut -d/ -f1)

# Verificar tipo de conta e plano
gh api repos/$REPO --jq '{owner_type: .owner.type, private: .private, plan: .owner.plan}'

# Testar se branch protection API esta disponivel (requer plano pago em repos privados)
STATUS=$(gh api repos/$REPO/branches/main/protection 2>&1)
if echo "$STATUS" | grep -q "Upgrade to GitHub Pro"; then
  PLAN_TYPE="free"
else
  PLAN_TYPE="paid"
fi

# Testar rulesets
RULESET_STATUS=$(gh api repos/$REPO/rulesets --method POST ... 2>&1)
# Mesmo erro 403 = free plan
```

**Regra:** repo privado + org free = forcar workaround Actions. Repo publico ou plano pago = usar protecao nativa.

### 2. Rota A — Plano pago (GitHub Team/Pro/Enterprise)

Usar GitHub Rulesets (mais moderno que branch protection classica):

```bash
gh api repos/$REPO/rulesets \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  --input - <<'EOF'
{
  "name": "Protect main - PR required",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "bypass_actors": [
    {
      "actor_id": 2,
      "actor_type": "Integration",
      "bypass_mode": "always"
    }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false
      }
    }
  ]
}
EOF
```

`bypass_actor_id: 2` = GitHub Actions Integration (permite que workflows de release / changelog continuem fazendo push direto).

Se a org for pessoal, tentar tambem o endpoint classico:
```bash
gh api repos/$REPO/branches/main/protection \
  --method PUT \
  --input - <<'EOF'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

### 3. Rota B — Plano gratuito (workaround reativo via GitHub Actions)

#### 3a. Habilitar permissoes de workflow na org e repo

**CRITICO:** Sem isso, `gh pr create` falha com `GitHub Actions is not permitted to create or approve pull requests`.

```bash
# Habilitar na org primeiro (pode dar 409 se ja habilitado em nivel superior)
echo '{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}' | \
  gh api orgs/$OWNER/actions/permissions/workflow --method PUT --input - 2>/dev/null || true

# Depois no repo
echo '{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}' | \
  gh api repos/$REPO/actions/permissions/workflow --method PUT --input -
```

**ERRO COMUM:** Usar `--field can_approve_pull_request_reviews:=true` — o `--field` trata o valor como string. Usar `--input -` com JSON valido.

#### 3b. Criar o workflow `.github/workflows/protect-main.yml`

**ARMADILHAS CRITICAS — lidas nesta ordem, todas ocorreram em producao:**

1. **`workflows: write` e INVALIDO para GITHUB_TOKEN** — nao esta na lista de permissoes suportadas. Causa falha silenciosa: 0 jobs, workflow name = filename. Nunca adicionar.

2. **em dash (`—`, U+2014) no `name:` quebra o parser Go do GitHub Actions** — usar apenas ASCII no campo `name:`.

3. **`if:` com `[bot]` sem aspas pode falhar** — sempre envolver em aspas duplas: `if: "github.actor != 'github-actions[bot]'"`.

4. **Strings multi-linha no `run: |` com `>` no inicio da linha** — o `>` e interpretado como YAML folded scalar se mal indentado. Usar `printf` + arquivo temporario para o corpo do PR.

5. **`set -euo pipefail` + force push** — o force push pode falhar se o push inclui arquivos de workflow (GITHUB_TOKEN nao tem `workflows:write`). Capturar com `|| true` e continuar para criar o PR.

6. **Escape de variaveis na expressao `if:`** — sempre passar valores do contexto via `env:`, nunca interpolacao direta `${{ github.actor }}` dentro de comandos `run:`.

Workflow correto:

```yaml
name: Protect main - block direct pushes

on:
  push:
    branches: [main]

permissions:
  contents: write
  pull-requests: write

jobs:
  guard:
    runs-on: ubuntu-latest
    if: "github.actor != 'github-actions[bot]' && github.event.before != '0000000000000000000000000000000000000000'"
    steps:
      - name: Verificar se push tem PR associado
        id: check
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          COMMIT_SHA: ${{ github.sha }}
          REPO: ${{ github.repository }}
        run: |
          for i in 1 2 3; do
            COUNT=$(gh api "repos/${REPO}/commits/${COMMIT_SHA}/pulls" \
              -H "Accept: application/vnd.github+json" \
              --jq 'length' 2>/dev/null || echo "0")
            echo "Tentativa $i - PRs: $COUNT"
            [ "$COUNT" != "0" ] && break
            [ "$i" -lt 3 ] && sleep 5
          done
          echo "pr_count=$COUNT" >> "$GITHUB_OUTPUT"

      - name: Resgatar push direto
        if: steps.check.outputs.pr_count == '0'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          REPO: ${{ github.repository }}
          BEFORE: ${{ github.event.before }}
          AFTER: ${{ github.sha }}
          ACTOR: ${{ github.actor }}
        run: |
          set -euo pipefail

          git clone "https://x-access-token:${GH_TOKEN}@github.com/${REPO}.git" repo
          cd repo
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

          BRANCH="direct-push/${ACTOR}/$(date +%Y%m%d-%H%M%S)"
          echo "Push direto detectado: ${BEFORE:0:7} -> ${AFTER:0:7} por ${ACTOR}"

          # Salvar commits do push em branch separada (sempre funciona)
          git checkout -b "$BRANCH" "$AFTER"
          git push origin "$BRANCH"

          # Tentar reverter main (falha silenciosa se push inclui arquivos de workflow)
          REVERTED=false
          git checkout main
          git reset --hard "$BEFORE"
          if git push --force-with-lease origin main 2>/dev/null; then
            REVERTED=true
          fi

          # Mensagem de acordo com resultado da reversao
          if [ "$REVERTED" = "true" ]; then
            REVERT_NOTE="Main foi revertida automaticamente para \`${BEFORE:0:7}\`."
          else
            REVERT_NOTE="Nao foi possivel reverter main automaticamente (push inclui arquivos de workflow). Reverter manualmente ou fechar este PR para descartar."
          fi

          printf '> [!WARNING]\n> Push direto a `main` detectado.\n\n**Autor:** @%s\n**Commits:** `%s` -> `%s`\n\n%s\n\nOs commits foram preservados nesta branch. Revisar e incorporar via merge neste PR.' \
            "$ACTOR" "${BEFORE:0:7}" "${AFTER:0:7}" "$REVERT_NOTE" > /tmp/pr-body.md

          gh pr create \
            --title "chore: resgate de push direto por @${ACTOR}" \
            --body "$(cat /tmp/pr-body.md)" \
            --base main \
            --head "$BRANCH"

          echo "Branch ${BRANCH} criada, PR aberto (revertido: ${REVERTED})"
```

#### 3c. Validar YAML antes de commitar

```bash
python3 -c "
import yaml
content = open('.github/workflows/protect-main.yml', 'rb').read()
# Verificar caracteres nao-ASCII (potencial problema no parser Go)
non_ascii = [(i, b) for i, b in enumerate(content) if b > 127]
if non_ascii:
    for pos, byte in non_ascii[:3]:
        line = content[:pos].count(b'\n') + 1
        print(f'AVISO: byte nao-ASCII 0x{byte:02x} na linha {line}')
yaml.safe_load(content.decode())
print('YAML OK')
"
```

### 4. Testar o workflow

Apos commitar e fazer push do workflow:

```bash
# Push de teste direto na main (sem PR)
git commit --allow-empty -m "test(ci): validate protect-main workflow"
git push

# Aguardar ~30s e verificar
sleep 30
gh api repos/$REPO/actions/runs --jq '.workflow_runs[:3] | .[] | {name,status,conclusion}'

# Verificar se PR foi criado
gh pr list

# Verificar se main foi revertida
git fetch origin && git log --oneline -3 origin/main
```

**Sinais de sucesso:**
- Run do workflow com nome correto (nao filename)
- Step "Verificar se push tem PR associado": 3 tentativas, count = 0
- Step "Resgatar push direto": branch criada, PR aberto
- `gh pr list` mostra PR `chore: resgate de push direto por @<actor>`

**Diagnostico de falhas por sintoma:**

| Sintoma | Causa | Fix |
|---------|-------|-----|
| Run com nome = filename, 0 jobs | YAML invalido no GitHub parser | Verificar em dash, `workflows:write`, `if:` nao-quotado |
| `workflows permission` error no force push | GITHUB_TOKEN nao suporta `workflows:write` | Usar `|| true`, nunca adicionar essa permission |
| `not permitted to create pull requests` | `can_approve_pull_request_reviews: false` | Habilitar via API na org e repo |
| Force push rejeitado permanentemente | Push inclui `.github/workflows/*.yml` | Comportamento esperado, PR ainda e criado |
| `[skip ci]` suprime o workflow | Commit de release usa `[skip ci]` | Esperado — bots de release devem ser excluidos do guard |

### 5. Atualizar AGENTS.md

Adicionar regra visivel antes das regras inegociaveis:

```markdown
## Regra de contribuicao

**Nunca fazer push direto na `main`.** Toda alteracao deve ser feita em branch separada e incorporada via PR.
Push direto e detectado automaticamente e revertido pelo workflow `protect-main.yml`.
```

### 6. Limpeza pos-teste

```bash
# Fechar PR de teste
gh pr list --json number,title | python3 -c "
import json,sys
prs = json.load(sys.stdin)
for pr in prs:
    if 'resgate de push direto' in pr['title'] or 'validate' in pr['title']:
        print(pr['number'])
" | xargs -I{} gh pr close {} --comment "PR de teste — workflow validado."

# Deletar branches de teste
gh api repos/$REPO/git/refs --jq '.[].ref' | grep 'direct-push' | \
  sed 's|refs/heads/||' | \
  while read branch; do
    gh api repos/$REPO/git/refs/heads/$branch --method DELETE
    echo "Deletada: $branch"
  done

# Sincronizar local com remote (que pode ter sido revertido)
git fetch origin && git reset --hard origin/main
```

---

## Comando: `status`

```bash
REPO=$(git remote get-url origin | sed 's/.*github\.com[:/]\(.*\)\.git/\1/')

# Verificar branch protection classica
gh api repos/$REPO/branches/main/protection 2>/dev/null | head -5

# Verificar rulesets
gh api repos/$REPO/rulesets 2>/dev/null | python3 -c "
import json,sys
rules = json.load(sys.stdin) if not isinstance(json.load(sys.stdin), dict) else []
" 2>/dev/null

# Verificar se workflow existe
ls .github/workflows/protect-main.yml 2>/dev/null && echo "Workflow presente" || echo "Sem workflow"

# Verificar permissoes de Actions
gh api repos/$REPO/actions/permissions/workflow --jq '.'
```

---

## Comando: `remove`

```bash
REPO=$(git remote get-url origin | sed 's/.*github\.com[:/]\(.*\)\.git/\1/')

# Remover branch protection classica
gh api repos/$REPO/branches/main/protection --method DELETE 2>/dev/null

# Remover rulesets (listar primeiro)
gh api repos/$REPO/rulesets --jq '.[].id' 2>/dev/null | \
  xargs -I{} gh api repos/$REPO/rulesets/{} --method DELETE

# Remover workflow
rm -f .github/workflows/protect-main.yml
git add .github/workflows/protect-main.yml
git commit -m "chore: remove protect-main workflow"
git push
```

---

## Notas de plataforma

| Cenario | Estrategia |
|---------|------------|
| Org free + repo privado | Workaround GitHub Actions (reativo) |
| Org free + repo publico | Rulesets ou branch protection nativa |
| GitHub Pro (usuario pessoal) | Branch protection nativa |
| GitHub Team/Enterprise | Rulesets com bypass para github-actions[bot] |
| Sem acesso admin ao repo | Nao e possivel configurar — informar ao usuario |

## Limitacoes do workaround reativo

- **Nao previne** — detecta e desfaz. Janela de ~30s onde o codigo esta na main
- Push de arquivos `.github/workflows/*.yml` — main nao e revertida automaticamente (limitacao do GITHUB_TOKEN)
- Multiplos pushes simultaneos — podem criar race condition
- Bot com permissao admin explicita — pode ser excluido do guard via `github.actor` check
