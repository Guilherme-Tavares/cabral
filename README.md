# cabral

Port scanner TCP/UDP em C++20, com interface de linha de comando e interface gráfica.

O nome faz referência às grandes navegações portuguesas, pela ideia de explorar e mapear
território desconhecido a partir de sondagens sucessivas.

Desenvolvido como atividade acadêmica, reimplementando em escopo reduzido funcionalidades
básicas do Nmap. Nenhuma linha de código do Nmap foi copiada: o comportamento de protocolo
vem das RFCs 791, 792, 793 e 1071, e o mapeamento porta → serviço vem de `/etc/services`,
nunca de `nmap-services`.

---

## Aviso de uso

**Use apenas contra máquinas que você possui ou tem autorização explícita para varrer.**

Varredura de portas sem autorização é, em muitas jurisdições, ilegal, e pode ser tratada
como tentativa de intrusão mesmo quando nenhuma conexão é estabelecida. Redes corporativas
e provedores costumam detectar e registrar esse tráfego.

Para experimentar sem risco:

- portas locais em `127.0.0.1`, abertas com `nc -l <porta>`
- máquinas virtuais na sua própria rede
- `scanme.nmap.org`, autorizado explicitamente pelo projeto Nmap para esse fim

---

## Compilação

Requer CMake 3.24+, Ninja e um compilador com suporte a C++20 (GCC 13+, Clang 16+ ou
MSVC 19.3x+). Nenhuma dependência externa é obrigatória no núcleo: apenas POSIX, Winsock e
a biblioteca padrão. GoogleTest, Dear ImGui e GLFW entram por `FetchContent` e apenas nos
alvos que os consomem.

### Linux

```bash
cmake --preset linux-debug
cmake --build --preset linux-debug
ctest --preset linux-debug
```

Para a interface gráfica, instale antes as dependências de sistema do GLFW:

```bash
sudo apt install libx11-dev libxrandr-dev libxinerama-dev \
                 libxcursor-dev libxi-dev libgl1-mesa-dev libxkbcommon-dev
```

### Windows

```powershell
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Os presets `debug` e `release` compilam em `build/`; os presets `linux-*` compilam em
`~/build-cabral/`, o que permite usar a mesma árvore de fontes nos dois sistemas sem que os
caches do CMake colidam.

Opções: `-DCABRAL_BUILD_GUI=ON|OFF` (padrão ON no Linux, OFF no Windows) e
`-DCABRAL_BUILD_TESTS=ON|OFF`.

---

## Privilégios

O connect scan (`-sT`) roda sem privilégio algum. SYN scan, a recepção de ICMP no UDP scan
e o ping sweep por ICMP precisam de raw sockets:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip build/cabral
```

**Não é preciso rodar como root.** O `setcap` concede exatamente as duas capabilities
necessárias, e nada além disso. O binário detecta a ausência delas na inicialização e
explica o que fazer, em vez de falhar com `EPERM` cru:

```
cabral: raw sockets require CAP_NET_RAW
  grant it once with:
      sudo setcap cap_net_raw,cap_net_admin=eip <path to cabral>
  or use -sT, which needs no privileges
```

O `setcap` se perde a cada recompilação, porque o binário é reescrito. Reaplique-o após
cada build.

---

## Uso

```
cabral [opções] <alvo>
```

### Tipos de varredura

| Flag | Varredura | Privilégio |
|------|-----------|------------|
| `-sT` | TCP connect (padrão) | nenhum |
| `-sS` | TCP SYN | `CAP_NET_RAW`, apenas Linux |
| `-sU` | UDP | opcional, ver limitações |
| `-sn` | apenas descoberta de hosts | opcional, ver limitações |

### Alvos

Aceita IPv4 literal, CIDR, faixa com hífen, lista separada por vírgula, hostname, e arquivo
com `-iL`:

```bash
cabral 192.168.1.10
cabral 192.168.1.0/24
cabral 192.168.1.10-40
cabral 192.168.1.1,192.168.1.5,10.0.0.1
cabral scanme.nmap.org
cabral -iL alvos.txt
```

Faixas acima de `/24` (256 endereços) exigem `--allow-large-range`. A guarda existe porque
um `/16` são 65 mil hosts, o que quase sempre é erro de digitação e não intenção.

### Portas

```bash
cabral -p 22 alvo             # uma porta
cabral -p 1-1024 alvo         # faixa
cabral -p 22,80,443 alvo      # lista
cabral -p - alvo              # todas, 1 a 65535
```

Sem `-p`, o padrão é `1-1024`. A porta 0 é recusada: é válida no protocolo, mas não é alvo
de varredura.

### Temporização

Perfis `-T0` (mais lento e discreto) a `-T5` (mais rápido e ruidoso), padrão `-T3`. Ajustam
timeout, retransmissões e paralelismo em conjunto. `--timeout <ms>` sobrepõe o timeout do
perfil.

### Saída

```bash
cabral -oN resultado.txt alvo    # texto, igual ao terminal
cabral -oJ resultado.json alvo   # JSON estruturado
cabral -v alvo                   # inclui portas filtradas e hosts inativos
cabral -vv alvo                  # mais detalhe de log
```

Sem `-v`, portas fechadas e filtradas são resumidas em uma linha, e hosts que não
responderam não geram relatório: numa varredura de `/24`, as centenas de ausentes
esconderiam os poucos que interessam.

### Exemplos

```bash
# serviços comuns em uma máquina da rede local
cabral -sT -p 22,80,443,3306,5432 192.168.1.10

# varredura rápida das portas privilegiadas, sem descoberta prévia
cabral -sS -Pn -T4 -p 1-1024 192.168.1.10

# quem está ativo na rede
cabral -sn 192.168.1.0/24

# serviços UDP mais comuns
cabral -sU -p 53,123,161 192.168.1.10
```

---

## Interface gráfica

```bash
./cabral-gui
```

Janela única com campo de alvo e portas, seleção de tipo de varredura e perfil de
temporização, barra de progresso ao vivo, tabela de resultados ordenável e colorida por
estado, e painel de log. Tipos que exigem privilégio aparecem desabilitados, com um tooltip
explicando o que falta, quando `CAP_NET_RAW` não está presente.

**Disponível apenas no Linux nesta entrega.**

---

## Estados de porta

| Estado | Significado |
|--------|-------------|
| `open` | serviço aceitou a conexão ou respondeu à sonda |
| `closed` | alvo recusou explicitamente (RST no TCP, ICMP port unreachable no UDP) |
| `filtered` | sem resposta, ou ICMP indicando bloqueio administrativo |
| `open\|filtered` | UDP sem resposta: aberta e filtrada são indistinguíveis |
| `unknown` | varredura cancelada ou sem privilégio para concluir |

`open|filtered` não é hesitação: é o estado correto para UDP sem resposta. Uma porta UDP
aberta que ignora a sonda e uma porta filtrada produzem exatamente o mesmo silêncio.
Reportar `open` ou `filtered` nesse caso seria afirmar algo que a evidência não sustenta.

---

## Limitações conhecidas

### Windows

- **`-sS` não é suportado.** A Microsoft bloqueia envio de TCP sobre raw socket desde o
  XP SP2, e nenhum nível de privilégio contorna isso. O binário recusa a varredura com
  mensagem explicativa, em vez de falhar no meio.
- **`-sU` reporta `open|filtered` no lugar de `closed`.** A recepção de ICMP unreachable
  não é confiável sem raw sockets, então portas fechadas não se distinguem das filtradas.
  Um aviso é emitido quando isso ocorre.
- **Sem interface gráfica** nesta entrega.
- O Windows Firewall descarta SYN silenciosamente, inclusive em loopback. Portas fechadas
  aparecem como `filtered` — resultado correto, mas diferente do que o mesmo comando produz
  no Linux.

### SYN scan

Ao receber o SYN/ACK, o kernel responde com RST porque não conhece a conexão que o scanner
forjou. Isso não impede a detecção, mas torna a varredura mais ruidosa e deixa rastro nos
registros do alvo. Para evitar:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

Aplique a regra com cuidado: enquanto ativa, ela afeta todo o tráfego TCP da máquina.

### UDP scan

Inerentemente lento. O kernel Linux limita a taxa de geração de ICMP unreachable
(`net.ipv4.icmp_ratelimit`), e o scanner respeita esse limite em vez de contorná-lo —
contorná-lo produziria resultados mais rápidos e menos confiáveis.

Portas 53, 123 e 161 recebem sondas específicas do protocolo (DNS, NTP, SNMP), que elevam
muito a taxa de resposta. Demais portas recebem datagrama vazio, que raramente provoca
resposta: por isso a maioria termina como `open|filtered`.

### Fora de escopo

Deliberadamente ausentes, por decisão de projeto e não por falta de tempo:

- **Detecção de versão de serviço.** O nome do serviço vem da porta registrada em
  `/etc/services`, não de sondagem do que responde. Uma porta 80 com SSH aparecerá como
  `http`.
- **OS fingerprinting**, **scripting**, **decoys** e **fragmentação**.
- **Varreduras FIN, Xmas e Null.** Dependem de comportamento que varia entre pilhas e são
  menos conclusivas que SYN.
- **IPv6.** Todo o código de rede assume IPv4; suportá-lo exigiria refazer a montagem de
  pacotes e a expansão de alvos.

---

## Estrutura

```
src/
├── core/                    # biblioteca estática scanner_core
│   ├── model/               # tipos de domínio, sem lógica de rede
│   ├── net/                 # sockets, checksums, montagem de pacotes
│   │   ├── posix/           # epoll, raw sockets
│   │   └── windows/         # select, Winsock
│   ├── scan/                # estratégias de varredura
│   ├── discovery/           # expansão de alvos, ping sweep
│   ├── services/            # porta → nome de serviço
│   └── ScanEngine.{hpp,cpp} # orquestração e concorrência
├── cli/                     # parser de argumentos, formatadores
└── gui/                     # janela ImGui, consome ScanEngine
```

O núcleo não conhece interface: CLI e GUI são consumidores independentes da mesma API
assíncrona. Não há código de rede em `src/gui/`, nem `iostream` em `src/core/`.

Código de plataforma é isolado em unidades de tradução separadas, selecionadas pelo CMake —
não há `#ifdef` espalhado pela lógica.

---

## Decisões de projeto

Escolhas que não são óbvias pelo código, registradas com o motivo:

**`Result<T, E>` em vez de `std::expected`.** O padrão do projeto é C++20, e
`std::expected` só chegou no C++23. `std::optional` sozinho carregaria o sucesso mas
descartaria a causa do erro — e no scanner a distinção entre conexão recusada e timeout é
exatamente o que separa `closed` de `filtered`. O tipo imita a forma de `std::expected`
para que a migração seja mecânica se o projeto subir de versão.

**`select` em vez de `WSAPoll` no Windows.** A `WSAPoll` não sinaliza falha de conexão em
socket não bloqueante — defeito reconhecido pela Microsoft e nunca corrigido. Verificado
aqui: com a conexão já recusada (`SO_ERROR == WSAECONNREFUSED`), ela retorna `0` e
`revents == 0`. Mantê-la faria toda porta recusada expirar por timeout e ser reportada
`filtered`, eliminando no Windows a distinção que `-sT` existe para fazer. O Linux não é
afetado: `epoll` reporta corretamente via `EPOLLERR`.

**Zeros à esquerda em IPv4 são recusados.** `192.168.01.1` falha em vez de virar
`192.168.1.1`. Na notação clássica `01` seria octal, e resolver a ambiguidade
silenciosamente faria o scanner mirar um endereço diferente do digitado.

**A porta 0 não é varrida.** É sintaticamente válida no protocolo, mas não é alvo útil, e
incluí-la em `1-1024` surpreenderia mais do que ajudaria.

**Cancelamento produz `unknown`, não `filtered`.** Uma varredura interrompida não observou
nada sobre as portas restantes. Reportá-las como filtradas seria inventar resultado.

**Tabela de serviços embutida escrita à mão.** O projeto lê `/etc/services` do sistema e
recorre a 41 entradas IANA embutidas quando ele não existe — no Windows, por exemplo. O
arquivo `nmap-services` não é usado: é dado licenciado sob NPSL.

---

## Licença

MIT. Ver [LICENSE](LICENSE).
