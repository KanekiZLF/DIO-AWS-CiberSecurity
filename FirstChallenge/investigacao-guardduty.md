# Relatório Técnico e Guia de Investigação: Amazon GuardDuty
## Incidente: UnauthorizedAccess:EC2/SSHBruteForce

Este documento consolida a análise técnica, hipóteses, matriz de evidências, estratégias de contenção e o histórico completo da investigação de segurança realizada sobre o achado do Amazon GuardDuty.

---

## 1. Contexto e Dados Confirmados do Ambiente

- **Tipo do Achado:** `UnauthorizedAccess:EC2/SSHBruteForce`
- **Severidade:** 8.0 (Alta)
- **Recurso Afetado:** Instância EC2 em sub-rede pública
- **Serviço Hospedado:** API de homologação de um e-commerce
- **Janela Temporal:** Entre 02h10 e 03h40 de uma terça-feira (horário de Brasília) — duração aproximada de 90 minutos
- **Descrição do GuardDuty:** Tentativas repetidas de login por SSH na porta 22, partindo de um único endereço IP externo
- **Configuração de Rede:** Security Group liberando a porta 22 para qualquer origem (`0.0.0.0/0`), herdado da criação do ambiente
- **Configuração de Autenticação:** Instância configurada para acesso exclusivo por par de chaves, sem autenticação por senha
- **Acessos Autorizados Conhecidos:** Time de desenvolvimento via SSH, a partir do escritório e da VPN corporativa
- **Monitoramento Ativo:** AWS CloudTrail habilitado na região e VPC Flow Logs ativos na VPC
- **Impacto de Negócio:** Se a instância sair do ar, o time de QA para suas atividades, mas nenhum cliente final é afetado

---

## 2. O Que Esse Achado Indica (Linguagem Direta)

O Amazon GuardDuty monitora eventos de rede analisando os **VPC Flow Logs** de forma passiva (sem necessidade de instalar agente na EC2). 

O achado `UnauthorizedAccess:EC2/SSHBruteForce` indica que a AWS identificou um padrão anômalo de tráfego de rede direcionado à porta 22 (SSH) da instância, originado de um único endereço IP externo. Esse endereço enviou uma quantidade massiva e repetitiva de pacotes de tentativa de conexão durante 90 minutos.

> **Importante:** Esse achado atesta a ocorrência de **tentativas insistentes de invasão**, mas **não confirma se o invasor obteve sucesso** em se autenticar no sistema operacional.

---

## 3. Decisão de Plantão: Derrubar o Acesso ou Continuar Investigando?

### Recomendação Operacional
**Não derrube (desligue ou encerre) a instância neste momento.** Em vez disso, execute a **contenção de rede imediata na porta 22**.

### Justificativa Técnica:
1. **Preservação de Evidências Voláteis:** Desligar a máquina limpa a memória RAM, destruindo processos maliciosos ativos, conexões de rede em aberto e artefatos de memória fundamentais caso haja necessidade de análise forense.
2. **Manutenção da Operação:** Como a API atende à equipe de QA, desligar a máquina causa indisponibilidade desnecessária caso tenha sido apenas um ataque bloqueado na fechadura.
3. **Contenção Sem Interrupção:** Ao restringir a regra do Security Group ou bloquear o IP na Network ACL (NACL), o tráfego do invasor é cortado na hora, mantendo a API ativa enquanto você realiza as checagens nos logs do Linux.

---

## 4. Hipóteses Investigativas (Da Mais Provável para a Menos Provável)

*Todas as opções abaixo são tratadas como hipóteses, dependentes de validação nos logs:*

1. **Hipótese 1 (Mais provável) — Varredura automatizada da internet sem sucesso:**  
   Robôs e scanners públicos na internet encontram servidores com a porta 22 exposta para `0.0.0.0/0` e disparam dicionários de credenciais automaticamente. Como a instância usa exclusivamente par de chaves e não aceita senhas, o ataque falhou sistematicamente durante os 90 minutos.
2. **Hipótese 2 (Moderadamente provável) — Tentativa com comprometimento bem-sucedido:**  
   O originador conseguiu acesso caso uma chave privada válida tenha vazado, caso tenha ocorrido alguma configuração acidental habilitando autenticação por senha para algum usuário local, ou pela exploração de uma vulnerabilidade no serviço SSH.
3. **Hipótese 3 (Menos provável) — Atividade legítima, teste interno ou falso positivo:**  
   Um colaborador ou rotina automatizada da empresa conectou-se de fora da VPN/escritório com uma chave incorreta de forma repetida, ou uma ferramenta de auditoria/segurança interna executou testes agendados.

---

## 5. Matriz de Evidências: Confirmação e Descarte

| Hipótese | Evidência que Confirma | Evidência que Descarta | Onde Encontrar |
| :--- | :--- | :--- | :--- |
| **Hipótese 1: Varredura sem sucesso** | Apenas mensagens de erro de conexão, pré-autenticação falha ou chave recusada vindas do IP atacante entre 02h10 e 03h40. Ausência de login aceito. | Presença de qualquer linha indicando autenticação aceita (`Accepted publickey` ou `Accepted password`) para o IP atacante. | **Linux:** `/var/log/secure` (Amazon Linux/RHEL) ou `/var/log/auth.log` (Ubuntu/Debian) e comando `lastb`. |
| **Hipótese 2: Comprometimento confirmado** | Registro explícito de sessão aceita vinculada ao IP de origem durante a janela temporal, seguido por processos ou conexões anômalas. | Ausência completa de entradas com o termo `Accepted` associadas ao IP atacante no intervalo investigado. | **Linux:** `/var/log/secure` ou `/var/log/auth.log`, e saída dos comandos `last`, `w`, `ss -tunap` e `ps aux`. |
| **Hipótese 3: Falso positivo / Atividade interna** | Confirmação formal de que o IP de origem pertence à empresa/colaborador autorizado ou ferramenta oficial de testes. | O IP de origem pertencer a provedores residenciais/servidores desconhecidos sem vínculo com a empresa e confirmação de ausência de testes. | **Rede/Infra:** Consulta WHOIS/RDAP do IP, logs da VPN corporativa e validação com o time de desenvolvimento. |

### Comandos Práticos no Linux para Investigação Imediata

Substitua `<IP_ORIGEM>` pelo endereço IP indicado no GuardDuty:

```bash
# 1. Verificar se houve autenticação com sucesso no período (Amazon Linux / RHEL):
grep "Accepted" /var/log/secure | grep "<IP_ORIGEM>"

# 1.1. Verificar se houve autenticação com sucesso no período (Ubuntu / Debian):
grep "Accepted" /var/log/auth.log* | grep "<IP_ORIGEM>"

# 1.2. Usando o journalctl (sistemas com systemd):
journalctl -u ssh --since "02:00" --until "04:00" | grep "Accepted"

# 2. Inspecionar histórico de logins bem-sucedidos e falhos:
last -n 30
lastb -n 30

# 3. Listar sessões atualmente ativas:
w
who

# 4. Checar conexões de rede ativas:
ss -tunap | grep ESTABLISHED

# 5. Listar processos com maior consumo de CPU/Memória:
ps aux --sort=-%cpu | head -n 15
```

---

## 6. Ações de Contenção (Classificadas por Reversibilidade)

### Ações Reversíveis (Recomendadas)

1. **Restringir a regra de entrada da porta 22 no Security Group:**
   - *Impacto:* Impede imediatamente acessos SSH vindos de fora das faixas autorizadas, mantendo a API de homologação no ar para o time de QA.
   - *Como executar:* Remover a regra `0.0.0.0/0` na porta 22 e permitir apenas os blocos CIDR do escritório e da VPN.

2. **Bloqueio do IP de Origem na Network ACL (NACL) da Sub-rede:**
   - *Impacto:* Bloqueia imediatamente todo o tráfego desse IP na borda da sub-rede sem afetar os acessos válidos.
   - *Como executar:* Adicionar uma regra de entrada com ação `DENY` para o IP de origem com número de prioridade menor (maior precedência) que as regras de permissão.

3. **Isolamento Total por Security Group de Quarentena (somente se a Hipótese 2 for confirmada):**
   - *Impacto:* Derruba imediatamente a API de homologação, paralisa os testes do time de QA e encerra qualquer conexão remota com a instância.
   - *Como executar:* Substituir os Security Groups da EC2 por um grupo exclusivo sem regras de entrada e sem regras de saída.

### Ações Não Reversíveis / Destrutivas (Evitar na Fase Inicial)

1. **Reiniciar ou desligar a instância EC2:**
   - *Impacto:* Apaga dados voláteis da memória RAM essenciais para análise forense e interrompe a API de homologação do time de QA.

2. **Terminar (destruir) a instância EC2:**
   - *Impacto:* Destrói permanentemente a máquina e seus volumes não persistidos, eliminando todas as evidências e paralisando o ambiente de homologação até recriação completa.

---

## 7. O Que Falta para Concluir e Fechar o Caso

Para cravar a conclusão definitiva entre falso alarme/ataque repelido ou incidente com invasão, é necessário:
1. Obter o valor exato do **endereço IP de origem** indicado no achado do GuardDuty.
2. Rodar a verificação de log no Linux (`grep Accepted`) para confirmar se houve ou não login aceito.
3. Consultar no console do Amazon GuardDuty se o IP de origem ou a EC2 possuem outros achados correlacionados (ex.: comunicação com Command & Control, tráfego DNS malicioso).
4. Verificar no AWS CloudTrail se foram realizadas chamadas de API usando a IAM Role da instância (caso exista) a partir das 02h10.
5. Alinhar com a equipe de desenvolvimento se houve uso deliberado de testes de carga ou tentativas fora da VPN.

---

## 8. Boas Práticas e Arquitetura Recomendada na AWS

Para erradicar definitivamente o risco de ataques de força bruta na porta 22:
- **AWS Systems Manager (SSM) Session Manager:** Permite acessar o terminal das instâncias EC2 via console ou CLI autenticado pelo IAM, sem abrir nenhuma porta de entrada em Security Groups e sem necessidade de IP público.
- **EC2 Instance Connect Endpoint (EICE):** Permite conexões SSH privadas através da rede da AWS sem expor a porta 22 diretamente à internet pública.
- **Princípio do Menor Privilégio em Rede:** Nunca manter regras administrativas (portas 22, 3389) abertas para `0.0.0.0/0`.

---

## 9. Histórico Integral de Prompts da Conversa

Abaixo estão registrados todos os prompts enviados pelo usuário ao longo desta sessão, organizados de forma cronológica, indentada e integral:

````markdown
### Prompt 1
    https://github.com/digitalinnovationone/dio-agent ja clonei esse repositorio. Crie uma pasta com você clonando por favor

### Prompt 2
    Você é um analista de segurança em nuvem e vai me ajudar a investigar um achado do Amazon GuardDuty.

    O achado:
    - Tipo: UnauthorizedAccess:EC2/SSHBruteForce
    - Recurso afetado: instância EC2 em uma sub-rede pública, que hospeda a API de homologação de um e-commerce
    - Severidade: 8.0, alta
    - Quando: entre 02h10 e 03h40 de uma terça-feira, horário de Brasília
    - O que o GuardDuty descreve: tentativas repetidas de login por SSH na porta 22, partindo de um único endereço IP externo, durante cerca de noventa minutos

    Quem vai ler sua resposta: a pessoa de plantão da equipe de infraestrutura, que conhece bem Linux e está começando agora em segurança na AWS.

    O que eu preciso ao final: decidir se derrubo o acesso à instância agora ou se continuo investigando antes de agir.

### Prompt 3
    Contexto do ambiente, até onde eu consigo confirmar hoje:
    - A instância hospeda a API de homologação. Se ela sair do ar, o time de QA para, mas nenhum cliente é afetado.
    - Quem acessa é só o time de desenvolvimento, por SSH, a partir do escritório e da VPN da empresa.
    - O security group libera a porta 22 para qualquer origem, herdado de quando o ambiente foi criado. CloudTrail está habilitado na região e os VPC Flow Logs estão ativos nessa VPC. A instância usa par de chaves, sem autenticação por senha.
    - Ainda não verifiquei se alguma tentativa de login teve sucesso, nem se o endereço de origem aparece em outros achados.

    Responda sempre nesta ordem:
    1. O que esse achado indica, em linguagem simples
    2. Hipóteses possíveis, da mais provável para a menos provável
    3. Para cada hipótese, qual evidência confirma e qual descarta, dizendo onde eu encontro essa evidência
    4. Contenção sugerida, separando o que é reversível do que não é
    5. O que ainda falta para fechar o caso

    Regras que você sempre segue:
    - Use apenas os dados que eu forneci. Nunca invente ID de instância, endereço IP de origem, número de conta, horário ou regra de security group.
    - Marque como hipótese tudo que não vier dos dados que eu dei.
    - Nunca conclua que é falso positivo sem dizer qual evidência sustentaria essa conclusão.
    - Antes de sugerir uma ação que derruba acesso, apaga recurso ou revoga credencial, diga o impacto dela em uma linha.
    - Se faltar informação para alguma etapa, diga exatamente o que falta em vez de preencher.

### Prompt 4
    Você é um analista de segurança em nuvem e vai me ajudar a investigar um achado do Amazon GuardDuty.

    O achado:
    - Tipo: UnauthorizedAccess:EC2/SSHBruteForce
    - Recurso afetado: instância EC2 em sub-rede pública, que hospeda a API de homologação de um e-commerce
    - Severidade: 8.0, alta
    - Quando: entre 02h10 e 03h40 de uma terça-feira, horário de Brasília
    - O que o GuardDuty descreve: tentativas repetidas de login por SSH na porta 22, partindo de um único endereço IP externo, durante cerca de noventa minutos

    Quem vai ler sua resposta: a pessoa de plantão da equipe de infraestrutura, que conhece bem Linux e está começando agora em segurança na AWS.

    O que eu preciso ao final: decidir se derrubo o acesso à instância agora ou se continuo investigando antes de agir.

    Contexto do ambiente, até onde eu consigo confirmar hoje:
    - A instância hospeda a API de homologação. Se ela sair do ar, o time de QA para, mas nenhum cliente é afetado.
    - Quem acessa é só o time de desenvolvimento, por SSH, a partir do escritório e da VPN da empresa.
    - O security group libera a porta 22 para qualquer origem, herdado de quando o ambiente foi criado. CloudTrail está habilitado na região e os VPC Flow Logs estão ativos nessa VPC. A instância usa par de chaves, sem autenticação por senha.
    - Ainda não verifiquei se alguma tentativa de login teve sucesso, nem se o endereço de origem aparece em outros achados.

    Responda sempre nesta ordem:
    1. O que esse achado indica, em linguagem simples
    2. Hipóteses possíveis, da mais provável para a menos provável
    3. Para cada hipótese, qual evidência confirma e qual descarta, dizendo onde eu encontro essa evidência
    4. Contenção sugerida, separando o que é reversível do que não é
    5. O que ainda falta para fechar o caso

    Regras que você sempre segue:
    - Use apenas os dados que eu forneci. Nunca invente ID de instância, endereço IP de origem, número de conta, horário ou regra de security group.
    - Marque como hipótese tudo que não vier dos dados que eu dei.
    - Nunca conclua que é falso positivo sem dizer qual evidência sustentaria essa conclusão.
    - Antes de sugerir uma ação que derruba acesso, apaga recurso ou revoga credencial, diga o impacto dela em uma linha.
    - Se faltar informação para alguma etapa, diga exatamente o que falta em vez de preencher.

    Se algum dado que você precisa para concluir não estiver acima, pergunte antes de responder.

### Prompt 5
    Agora faça o seguinte, peegue tudo oque mee explicou, crie um .md de forma extremamente organizada, explicando os pontos, não invente nada, oque não souber, use a internet e se informe. dito isso, no final de toda a explicação, coloque todos os prompts usados em nossa conversa, de forma extremamente organizada e indentada ! Incluindo esse prompt !
````
