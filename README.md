# 🛡️ Env-Shield

**Git pre-commit hook** escrito en **Go** con concurrencia y memoria constante que bloquea commits con credenciales antes de que lleguen al repositorio.

---

## Requisitos

| Dependencia | Versión | ¿Por qué? |
|-------------|---------|-----------|
| **Go** | 1.22+ | Compilar y ejecutar el binario |
| **Git** | 2.0+ | Acceder a staged files y hooks |

> **0 dependencias externas.** Todo usa la stdlib de Go (`bufio`, `regexp`, `math`, `os/exec`, `sync`).

---

## Instalación

### Paso 1: Instalar Go

**Windows (recomendado):**
```cmd
winget install GoLang.Go --accept-source-agreements
```

**O descarga el instalador:** https://go.dev/dl/

**Linux:**
```bash
sudo apt install golang-go        # Debian/Ubuntu
sudo dnf install golang           # Fedora
sudo pacman -S go                 # Arch
```

**macOS:**
```bash
brew install go
```

**Verificar instalación:**
```bash
go version
# → go version go1.26.2 windows/amd64
```

### Paso 2: Clonar y compilar

```bash
git clone https://github.com/hunkak03/env-shield.git
cd env-shield
go build -o env-shield .
```

En Windows se genera `env-shield.exe`. En Linux/macOS se genera `env-shield`.

### Paso 3: Instalar el hook en tu repo

```bash
cd tu-repo-git
<path-a>/env-shield install
```

Esto crea automáticamente `.git/hooks/pre-commit` y configura Git para usarlo.

---

## Comandos

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `env-shield install` | Instala el hook en el repo actual | `env-shield install` |
| `env-shield scan` | Escanea archivos en staging | `git add . && env-shield scan` |
| `env-shield init` | Crea `.env-shield.json` con config por defecto | `env-shield init` |
| `env-shield version` | Muestra la versión | `env-shield version` |
| `env-shield help` | Muestra ayuda | `env-shield help` |

### Flujo típico

```bash
# 1. Instalar (una vez por repo)
env-shield install

# 2. Trabajar normalmente
echo 'API_KEY = "AKIAIOSFODNN7EXAMPLE"' > config.go
git add config.go
git commit -m "add config"

# ← Env-Shield detecta el secreto y BLOQUEA el commit automáticamente
```

---

## Detección: 3 Capas

### Capa 1 — Regex (Firmas conocidas)

16 patrones precompilados que detectan:

| Proveedor | Patrón | Ejemplo |
|-----------|--------|---------|
| **AWS** | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| **AWS Secret** | Asignación contextual | `aws_secret_access_key = wJalr...` |
| **Stripe** | `sk_live_...`, `rk_live_...`, `pk_live_...` | `sk_live_abc123...` |
| **Google API** | `AIza...` | `AIzaSyA1B2C3D4...` |
| **Google OAuth** | `ya29....` | `ya29.a0AfH...` |
| **GitHub PAT** | `ghp_...` | `ghp_ABCDEF...` |
| **GitHub OAuth** | `gho_...` | `gho_ABCDEF...` |
| **GitHub Fine-Grained** | `github_pat_...` | `github_pat_11A...` |
| **Slack Bot** | `xoxb-...` | `xoxb-12345...` |
| **Slack User** | `xoxp-...` | `xoxp-12345...` |
| **Private Keys** | `-----BEGIN ... PRIVATE KEY-----` | PEM headers |
| **JWT** | `eyJ....` | `eyJhbGciOi...` |
| **DB Strings** | `mongodb://`, `postgres://`, `mysql://`, `redis://` | Connection URIs |
| **Genérico** | `api_key = "..."`, `token = "..."` | Asignaciones de variables |

### Capa 2 — Entropía de Shannon

Identifica cadenas con **entropía ≥ 4.5** en asignaciones de variables. Detecta tokens genéricos que no encajan en ningún patrón fijo.

```python
# Esto se detecta por alta entropía aunque no sea un patrón conocido
TOKEN = "xK9mP2vLqR7nW4jTsY8aB3cD5eFgH"
# Entropía: 4.72 → DETECTADO
```

### Capa 3 — Archivos prohibidos

Bloquea por nombre o extensión:

| Tipo | Archivos |
|------|----------|
| **Entorno** | `.env`, `.env.local`, `.env.production`, `.env.staging` |
| **Certificados** | `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore` |
| **SSH Keys** | `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` |
| **Credenciales** | `credentials.json`, `service-account.json` |
| **Config sensibles** | `.npmrc`, `.pypirc`, `.dockercfg`, `.htpasswd` |

---

## Configuración

Genera el archivo por defecto:
```bash
env-shield init
```

Crea `.env-shield.json`:
```json
{
  "ignore_files": [
    "test/fixtures/keys.pem"
  ],
  "ignore_patterns": [
    "\\.test\\.",
    "\\.spec\\."
  ],
  "entropy_threshold": 4.5,
  "min_secret_length": 16
}
```

| Opción | Descripción | Default |
|--------|-------------|---------|
| `ignore_files` | Rutas exactas de archivos a ignorar | `[]` |
| `ignore_patterns` | Regex patterns de archivos a ignorar | `["\.test\.", "\.spec\."]` |
| `entropy_threshold` | Umbral de entropía (0-8, mayor = más estricto) | `4.5` |
| `min_secret_length` | Longitud mínima para detección por entropía | `16` |

---

## Bypass

### Ignorar una línea concreta

Añade un comentario con `env-shield-ignore`:

```go
var TestKey = "AKIAIOSFODNN7EXAMPLE" // env-shield-ignore
```

### Ignorar un archivo entero

Añádelo a `ignore_files` en `.env-shield.json`:

```json
{
  "ignore_files": ["test/testdata/secret.pem"]
}
```

---

## Ejemplo de output

```
============================================================
  🛡️  Env-Shield: SECRETS DETECTED!
============================================================
  Found 2 potential secret(s) in staged files.
  Commit BLOCKED to prevent credential leakage.
============================================================

  [1] File: config/settings.go
      Line: 15
      Type: AWS Access Key ID
      Layer: regex
      Value: AKIA...MPLE

  [2] File: .env
      Line: N/A
      Type: Forbidden File
      Layer: forbidden_file
      Value: .env

============================================================
  💡 To bypass, add "// env-shield-ignore" to the line
     or add the file to ".env-shield.json" ignore list.
============================================================
```

---

## Arquitectura

### Worker Pool Concurrente

```
┌─────────────────────────────────────────────────────┐
│                   ScanStagedFiles                    │
│                                                      │
│  git diff --cached ──► Lista de archivos             │
│                              │                       │
│                    ┌─────────▼─────────┐             │
│                    │   Jobs Channel    │             │
│                    │  (chan FileJob)   │             │
│                    └─────────┬─────────┘             │
│              ┌───────────────┼───────────────┐       │
│              │               │               │       │
│         ┌────▼───┐    ┌─────▼────┐   ┌──────▼──┐    │
│         │Worker 1│    │Worker 2  │   │Worker N │    │
│         │        │    │          │   │         │    │
│         │stream  │    │stream    │   │stream   │    │
│         │line × N│    │line × N  │   │line × N │    │
│         └────┬───┘    └─────┬────┘   └──────┬──┘    │
│              └───────────────┼───────────────┘       │
│                    ┌─────────▼─────────┐             │
│                    │ Results Channel   │             │
│                    │ (chan FileResult) │             │
│                    └─────────┬─────────┘             │
│                              ▼                       │
│                    Findings agregados                │
└─────────────────────────────────────────────────────┘
```

### Memoria Constante O(1)

Cada archivo se procesa como un **stream** — línea a línea vía `bufio.Scanner` pipeado desde `git show :<file>`. **Nunca** se carga el contenido completo en memoria.

```
git show :config.py ──► stdout pipe ──► bufio.Scanner ──► procesa línea N
                              │
                        Nunca se bufferiza
                        en memoria de la app
```

| Métrica | Valor |
|---------|-------|
| **Memoria por worker** | O(1) — independiente del tamaño del archivo |
| **Throughput** | O(n/m) donde n = archivos, m = workers |
| **Workers simultáneos** | 8 (`MaxWorkers`) |
| **Allocs en hot path** | 0 — todo usa mapas de frecuencia en stack |

---

## Tests

```bash
# Todos los tests (40 total)
go test ./... -v

# Solo unit tests
go test ./core -v -run "Test(CalculateEntropy|Obfuscate|Detect)"

# Benchmarks
go test ./core -bench=. -benchmem

# Solo integration tests (requiere git)
go test ./core -run "TestIntegration" -v
```

**Resultado:**
```
=== RUN   TestCalculateEntropy_Empty          → PASS
=== RUN   TestDetectRegexSecrets_AWSAccessKey → PASS
=== RUN   TestDetectForbiddenFile_EnvFile     → PASS
=== RUN   TestIntegration_ScanStagedFiles_AWSSecret → PASS
...
40/40 tests passing
```

---

## Estructura del proyecto

```
env-shield/
├── main.go                     # CLI entry point (install, scan, init, help)
├── go.mod                      # Go module definition
├── env-shield / env-shield.exe # Binario compilado
├── README.md                   # Esta documentación
└── core/
    ├── detector.go             # Motor de detección + worker pool
    ├── detector_test.go        # 34 unit tests + 6 benchmarks
    ├── integration_test.go     # 6 E2E tests con repos git reales
    ├── output.go               # Formateo de output en consola
    └── install.go              # Instalación de hooks + gestión de config
```

---

## Troubleshooting

### `go: command not found`

Go no está en el PATH. Reinicia la terminal o añade Go manualmente:

**Windows:**
```cmd
set PATH=C:\Program Files\Go\bin;%PATH%
```

**Linux/macOS:**
```bash
export PATH=$PATH:/usr/local/go/bin
```

### `error: cannot spawn .git/hooks/pre-commit`

Problema con hooks en Windows. Solución:
```bash
git config core.hooksPath ".git/hooks"
```
O reinstala el hook: `env-shield install`

### Detecta falsos positivos en tests

Añade `// env-shield-ignore` a la línea o excluye archivos de test en `.env-shield.json`:
```json
{
  "ignore_patterns": ["\\.test\\.", "\\.spec\\.", "test_"]
}
```

### Quiero desinstalar el hook

```bash
# Opción 1: Eliminar el archivo
rm .git/hooks/pre-commit

# Opción 2: Restaurar hooks por defecto de git
git config --unset core.hooksPath
```

---

## Licencia

Este proyecto está bajo la licencia [MIT](https://opensource.org/licenses/MIT) — úsalo, modifícalo y compártelo libremente.

```
MIT License — Copyright (c) 2026 Hunkak03
```

---

> Hecho con **cariño** y **pasión** por [Hunkak03](https://github.com/Hunkak03) 💚
