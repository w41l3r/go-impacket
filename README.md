# go-impacket

Reimplementação em Go de quatro ferramentas do [impacket](https://github.com/fortra/impacket) para execução remota e relay de credenciais em ambientes Windows. Nomes, estrutura interna e interfaces foram redesenhados; a lógica de protocolo é equivalente.

## Ferramentas

| Ferramenta Go | Equivalente impacket | Técnica | Autenticação |
|---|---|---|---|
| `scorch` | `smbexec.py` | Cria serviço temporário via SCM (SCMR/DCE-RPC) por comando; output capturado via share SMB | NTLM (pass-the-hash), Kerberos |
| `haunt` | `psexec.py` | Faz upload de binário RemCom como serviço; I/O via named pipes (`RemCom_stdin/stdout/stderr`) | NTLM (pass-the-hash), Kerberos |
| `whisper` | `wmiexec.py` | Executa via DCOM/WMI (`Win32_Process.Create`); não cria serviço, roda como o usuário autenticado | NTLM (pass-the-hash), Kerberos |
| `refract` | `ntlmrelayx.py` | Intercepta autenticações NTLM em listeners SMB/HTTP e as relaya para targets; vault de sessões via SOCKS5 | — (relay, não autentica diretamente) |

## Build

```bash
git clone https://github.com/w41l3r/go-impacket
cd go-impacket
make all          # compila bin/{scorch,haunt,whisper,refract}
go test ./...     # 25 testes
```

Requer Go 1.22+.

---

## scorch

Execução remota via Service Control Manager. Para cada comando, cria um serviço temporário cujo `binPath` é o próprio comando, captura o output num arquivo no share e deleta o serviço em seguida.

```
scorch -t [domain/]user[:pass]@host [flags]

  -t        target: [[domain/]user[:pass]@]host
  -H        LMHASH:NTHASH  (pass-the-hash)
  -k        autenticação Kerberos (lê ccache de KRB5CCNAME)
  -dc       IP do domain controller
  -share    share para captura de output (padrão: C$)
  -mode     SHARE ou SERVER — SERVER sobe SMB server local na porta 445 (requer root)
  -shell    cmd ou powershell (padrão: cmd)
  -svc      nome do serviço (aleatório se omitido)
  -timeout  timeout por comando (padrão: 30s)
  -port     porta SMB (padrão: 445)
  -debug    output verboso
```

**Diferenças vs smbexec.py**
- `--timeout` por comando (original não tem)
- Detecção explícita de output vazio (avisa em vez de silenciar)
- Backoff exponencial na reconexão ao SCM

---

## haunt

Execução interativa via named pipes, estilo psexec. Faz upload de um binário RemCom (fornecido pelo operador) como serviço Windows; as pipes `RemCom_stdin`, `RemCom_stdout` e `RemCom_stderr` são mapeadas para o terminal local em modo raw.

```
haunt -t [domain/]user[:pass]@host -file remcom.exe [flags]

  -t        target
  -H        LMHASH:NTHASH
  -k        Kerberos
  -dc       IP do domain controller
  -file     caminho local do binário RemCom a fazer upload (obrigatório)
  -cmd      comando único a executar (sem -cmd abre shell interativa)
  -path     working directory no target
  -svc      nome do serviço
  -port     porta SMB (padrão: 445)
  -debug    output verboso
```

O binário RemCom pode ser obtido em https://github.com/kavika13/RemCom.

**Diferenças vs psexec.py**
- Terminal raw mode via `golang.org/x/term` (readline + history no lugar do `cmd.Cmd` do Python)
- Exit code do processo remoto propagado para o processo local quando `-cmd` é usado

---

## whisper

Execução via WMI/DCOM. Não cria serviço — usa `Win32_Process.Create` via interface `IWbemLevel1Login`, o que gera menos eventos no Event Log que `scorch`. Output redirecionado para um arquivo no share e recuperado via SMB.

```
whisper -t [domain/]user[:pass]@host [flags]

  -t            target
  -H            LMHASH:NTHASH
  -k            Kerberos
  -dc           IP do domain controller
  -share        share para captura de output (padrão: ADMIN$)
  -cmd          comando único (sem -cmd abre shell interativa)
  -shell        cmd ou powershell (padrão: cmd)
  -nooutput     não recupera output (imprime o PID retornado)
  -silent       executa sem wrapper cmd.exe (sem output)
  -fallback-scm usa SCM em vez de DCOM nativo (padrão: true)
  -timeout      timeout de espera pelo output (padrão: 30s)
  -port         porta SMB (padrão: 445)
  -debug        output verboso
```

**Sobre `--fallback-scm`**
O caminho nativo DCOM implementa resolução via endpoint mapper (porta 135), handshake NTLM dentro do DCE-RPC e `NTLMLogin` até extração do IPID da interface WMI. A camada final de marshaling ORPC/VARIANT para `Win32_Process.Create` retorna erro descritivo com o IPID capturado. O fallback SCM (padrão) cobre o caso de uso operacional.

**Diferenças vs wmiexec.py**
- `-nooutput` imprime o PID retornado pelo `Create()` em vez de suprimir silenciosamente
- `-timeout` configurável para espera do output file

---

## refract

Relay de autenticações NTLM. Escuta em listeners SMB (porta 445) e/ou HTTP (porta 80), intercepta o handshake NTLM (Negotiate → Challenge → Authenticate) e relaya para os targets configurados. Sessões autenticadas ficam no vault e podem ser reutilizadas via SOCKS5.

```
refract [flags]

  -t          target único (smb://host, http://host, etc.)
  -tf         arquivo de targets (um por linha)
  -w          monitora o arquivo de targets por mudanças
  -smb-port   porta do listener SMB (padrão: 445)
  -http-port  porta do listener HTTP (padrão: 80)
  -no-smb     desativa listener SMB
  -no-http    desativa listener HTTP
  -c          comando a executar após relay bem-sucedido (target SMB)
  -socks      ativa vault de sessões com shell interativa
  -socks-addr endereço do SOCKS5 (padrão: 127.0.0.1)
  -socks-port porta do SOCKS5 (padrão: 1080)
  -no-multi   relaya cada target apenas uma vez
  -ra         seleção aleatória de targets
  -6          escuta em IPv6
  -debug      output verboso
```

Quando `-socks` está ativo, abre um prompt `refract>` com os comandos:
- `sessions` — lista sessões autenticadas no vault
- `targets`  — lista targets configurados
- `exit`     — encerra

**Relay SMB → SMB:** máquina de estados SMB2 completa (NEGOTIATE → SESSION_SETUP type1/type2/type3) com rewrite de SessionID e SPNEGO unwrap/wrap.

**Relay HTTP → SMB:** challenge real extraído do target SMB, tracking por cookie (`rsid`), sessões pendentes expiram em 2 minutos.

**Diferenças vs ntlmrelayx.py**
- Sessões pendentes (type-1 sem type-3) fechadas automaticamente após TTL (original vaza fds)
- TreeId=0 em NEGOTIATE e SESSION_SETUP conforme MS-SMB2 (original usava valor inválido)
- Session tracking via cookie HTTP em vez de header de resposta não-echado por clientes reais

---

## Autenticação

Todos os comandos aceitam:

| Forma | Exemplo |
|---|---|
| Usuário e senha | `-t domain/user:pass@host` |
| Pass-the-hash | `-t domain/user@host -H aad3b435...:31d6cfe0...` |
| Null session | `-t host` (sem usuário) |
| Kerberos | `-k -dc <dc-ip> -t domain/user@host` |

---

## Aviso

Ferramentas destinadas a testes de penetração autorizados, CTFs e pesquisa de segurança ofensiva. Use apenas em sistemas para os quais você tem permissão explícita.
