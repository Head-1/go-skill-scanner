# go-skill-scanner

Security scanner para AI agent skills.

## Características
- YARA + AST
- Docker-first
<<<<<<< HEAD
# go-skill-scanner
=======

#🔍 go-skill-scanner
>>>>>>> f331d26 (feat: refatoração de elite, integração Cobra CLI e documentação de arquitetura)

Security Scanner for AI Agent Skills — Uma ferramenta de análise de segurança para skills 
de agentes de IA, escrita em Go.


==================================================
SOBRE O PROJETO
==================================================

O go-skill-scanner é uma refatoração em Go do Cisco AI Skill Scanner 
(https://github.com/cisco-ai-defense/skill-scanner), projetado para detectar 
padrões maliciosos em skills de agentes de IA, como:

- Exfiltração de dados (comandos curl, wget, sockets)
- Injeção de código (eval, exec, system)
- Ofuscação (base64, hex, strings codificadas)


==================================================
CARACTERÍSTICAS
==================================================

- Multi-engine: YARA + AST (Análise de Árvore Sintática)
- Docker-first: Imagem mínima baseada em scratch (~15MB)
- Air-gapped ready: Funciona completamente offline
- Binário estático: Sem dependências externas
- Regras Cisco: Fetch automático das regras oficiais


==================================================
INSTALAÇÃO RÁPIDA
==================================================

Via Go:
  go install github.com/Head-1/go-skill-scanner/cmd/scanner@latest

Via Docker:
  docker pull ghcr.io/head-1/go-skill-scanner:latest

Compilar do código fonte:
  git clone https://github.com/Head-1/go-skill-scanner.git
  cd go-skill-scanner
  make build


==================================================
USO BÁSICO
==================================================

Scan simples:
  scanner scan ./caminho/para/skill

Scan com análise AST:
  scanner scan ./caminho/para/skill --use-ast

Scan completo (YARA + AST):
  scanner scan ./caminho/para/skill --use-yara --use-ast

Scan de múltiplas skills:
  scanner scan-all ./diretorio/de/skills --recursive

Saída em formato SARIF (para CI/CD):
  scanner scan ./skill --format sarif --output report.sarif

Usando Docker:
  docker run --rm -v $(pwd):/workspace ghcr.io/head-1/go-skill-scanner scan /workspace/skill


==================================================
ARQUITETURA
==================================================

O scanner opera em camadas progressivas de análise:

    ┌─────────────────┐
    │   YARA Rules    │ → Padrões conhecidos
    ├─────────────────┤
    │   AST Analysis  │ → Heurísticas estruturais
    ├─────────────────┤
    │   LLM-as-Judge  │ → Análise semântica (futuro)
    └─────────────────┘
             ↓
       [Resultado JSON/SARIF]


==================================================
ROADMAP
==================================================

Fase 0: Estrutura inicial e schema ................. ✅ Concluído
Fase 1: Motor YARA (regras Cisco) .................. 🚧 Em desenvolvimento
Fase 2: Análise AST ................................ ⏳ Planejado
Fase 3: Meta-analyzer (filtro de falsos positivos) . ⏳ Planejado
Fase 4: Integração LLM ............................. 🔮 Futuro


==================================================
CONTRIBUINDO
==================================================

Contribuições são bem-vindas!

Como contribuir rapidamente:
1. Faça um fork do projeto
2. Crie sua branch (git checkout -b feature/nova-feature)
3. Commit suas mudanças (git commit -m 'feat: adiciona nova feature')
4. Push para a branch (git push origin feature/nova-feature)
5. Abra um Pull Request


==================================================
LICENÇA
==================================================

Este projeto está licenciado sob a GNU General Public License v3.0.

Third-Party Components:
- Regras YARA Cisco: Cisco AI Skill Scanner (Apache 2.0)
- go-yara: Biblioteca YARA para Go (BSD-3)


==================================================
CONTATO
==================================================

GitHub: @Head-1
Repositório: https://github.com/Head-1/go-skill-scanner


⭐ Se este projeto te ajudou, considere dar uma estrela!
<<<<<<< HEAD
headmaster@npcaia-daemon:~/go-skill-scanner$ 
=======
