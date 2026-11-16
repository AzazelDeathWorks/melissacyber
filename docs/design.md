# Aegis — Açık Kaynak Cyber Harness: Derin Teknik Plan (v2)

> Durum: Kod yazılmadı. Bu belge araştırma + mimari tasarımdır.

## 0. Araştırma özeti (kısa)

Kaynaklar: XBOW webinar/blog analizi, DARPA AIxCC kazananı Team Atlanta ATLANTIS teknik raporu, Google Project Naptime→Big Sleep ilkeleri, Anthropic cyber-range değerlendirmeleri, OpenAI sistem kartları, ve açık kaynak saha (Strix ~75k★, Decepticon, Shannon, CAI, Nebula, HackingBuddyGPT, EnIGMA, PyRIT, OSS-CRS).

Rakiplerden çıkarılan 6 altın kural:
1. **Coordinator + kısa ömürlü solver'lar** (XBOW) — tek devasa ajan değil, orkestra.
2. **AI'sız deterministik doğrulama** (XBOW) — 0 false positive'ın tek yolu.
3. **Ortogonal ensemble** (Atlantis) — aynı işi farklı stratejiyle yapan paralel motorlar.
4. **İnteraktif araçlar + reasoning alanı + mükemmel doğrulama + sampling** (Naptime).
5. **İnteraktif terminal ajanları** (EnIGMA/Decepticon) — debugger/msfconsole gibi TTY araçları şart.
6. **Standart araçlar yeterli** (Anthropic) — sihir araçta değil, harness'ta.

Boşluk: hiçbiri bunların hepsini + **gerçek red↔blue kapalı döngüyü** tek açık kaynak sistemde vermiyor.

---

## 1. Sandbox: Docker mı, Firecracker mı?

**Cevap: ikisi de — tak-çalıştır backend, risk seviyesine göre.**

| Seviye | Backend | Ne zaman | Sınır |
|---|---|---|---|
| `local` (varsayılan) | Docker + hardening | Tek kullanıcı, kendi makinesi, yetkili test | Linux namespace + cgroup + seccomp + cap-drop + `no-new-privileges` + read-only root |
| `local+` | Docker üzerinde **gVisor (runsc)** | Exploit kodu çalıştırılacaksa, güvensiz hedefler | User-space kernel (Sentry) syscall'ları karşılar; host kernel'e ~350 yerine birkaç düzine syscall yüzeyi |
| `cloud` / `multi-tenant` | **Firecracker microVM** (Kata veya doğrudan jailer) | Hosted mod, çok kullanıcılı kurulum, hedef düşman ortam olabilir | Donanım sanallaştırma sınırı: her engagement kendi guest kernel'i, milisaniye boot, snapshot desteği |

Gerekçe: sandbox'ın işi iki yönlü — (a) ajanın/exploit'in operatör makinesine zarar vermesini engelle, (b) engagement'ları birbirinden izole et. E2B/Vercel/Anthropic'in yaptığı da bu ayrım (E2B+Vercel=Firecracker, Claude Code=gVisor). Tek makinede tek kullanıcı için Docker+gVisor pratikte yeterli; Firecracker'ı "hosted/cloud" profiline koyarız — böylece `pip install aegis` kolaylığından ödün vermeyiz.

**Sandbox içi düzen** (her engagement):
- 1 "attack box" (Kali tabanlı imaj, araç seti kurulu)
- Yan konteynerler: egress proxy (Squid, **default-deny allowlist** = scope'un ağ seviyesi hali), HTTP interception proxy (Caido/mitmproxy), OOB canary sunucusu, evidence store
- Ağ: `aegis-net` köprüsü; hedefe çıkış SADECE egress proxy üzerinden → scope ihlali prompt'a değil iptables/proxy kuralına bağlı (Strix'in yapmadığı fark)
- Lab modu: hedef de konteyner olabilir (AutoPenBench/VulnHub imajları)

## 2. Agent kadrosu — kaç agent?

**Cevap: ~40 ajan tipi, engagement başına 30–80 canlı ajan, yüzlerce–binlerce kısa ömürlü solver instance'ı** (XBOW "binlerce ajan" diyor; bizde bütçe sınırı var).

### Katman 0 — Orkestrasyon (1 ajan)
| Ajan | Görev | Model profili |
|---|---|---|
| **Coordinator** | OPPLAN okur, task graph üretir, solver spawn/retire eder, debrief yapar, sonraki hamleyi önceliklendirir | Frontier (en güçlü model) |

### Katman 1 — Discovery (6 ajan tipi)
| Ajan | Görev |
|---|---|
| `recon-osint` | Subdomain, DNS, ASN, sertifika, breach verisi, GitHub sızıntısı |
| `surface-mapper` | Port/servis taraması, teknoloji parmak izi |
| `web-crawler` | Headless browser ile canlı endpoint/parametre/auth-flow haritası (XBOW'un 530 endpoint bulduğu katman) |
| `api-mapper` | OpenAPI/GraphQL/gRPC şema çıkarımı, gizli endpoint tahmini |
| `code-mapper` | Kaynak varsa: mimari, trust boundary, data-flow, SAST ön-analiz (Shannon deseni) |
| `cloud-recon` | AWS/Azure/GCP asset + IAM yüzeyi (cloud engagement'larda) |

### Katman 2 — Solver havuzu (18 ajan tipi, isteğe bağlı spawn)
Her biri tek zafiyet sınıfında uzman, taze context'le doğar, görev bitince emekli:
`inj-sqli`, `inj-nosql`, `inj-cmd`, `inj-ssti`, `xss`, `ssrf`, `authn`, `authz-idor`, `session-jwt`, `deserialization`, `file-path` (LFI/RFI/upload), `xxe`, `smuggling`, `cors`, `races-logic` (business logic + race), `crypto`, `ad-kerberos` (AD engagement), `binary-pwn` (lab/CTF)

### Katman 3 — Destek ajanları (9 ajan tipi)
| Ajan | Görev |
|---|---|
| `payload-forge` | Context'e özel payload/WAF bypass varyasyonları üretir |
| `chain-composer` | Tek başına düşük bulguları zincirler (SSRF→cloud creds→data gibi) |
| `creds-manager` | Token/cookie/session yaşam döngüsü, re-auth |
| `critic` | Bulguları kırmızı-takımlar: "bu gerçek mi, alternatif açıklama ne?" (slop kesici) |
| `dedup-triage` | Bulgu birleştirme, severity önerisi |
| `summarizer` | Uzun context'i sıkıştırır (EnIGMA deseni) |
| `report-writer` | Bug-bounty kalitesinde yazım |
| `repro-qa` | PoC'yi temiz ortamda tekrar koşturur |
| `human-liaison` | HITL onay kapısı, kullanıcıya soru |

### Katman 4 — Blue team (6 ajan tipi)
| Ajan | Görev |
|---|---|
| `patch-dev` | Bulguya patch üretir, derler, mevcut testleri koşturur |
| `retest` | Patch sonrası aynı exploit'i tekrar dener (XBOW verify) |
| `detection-eng` | TTP→MITRE ATT&CK map → Sigma/Suricata/YARA kuralı |
| `replay` | Saldırıyı lab'da tekrar oynatıp kuralın alarm verdiğini doğrular |
| `hardening-auditor` | Konfig/header/TLS/IAM hardening checklist |
| `vaccine-orchestrator` | attack→patch→retest→detect döngüsünü yönetir |

### Ölçek matematiği
Tipik web engagement: 1 coordinator + 5 discovery + ~12 aktif solver + 4 destek ≈ **22 canlı ajan**; solver instance'ları görev başına yenilendiği için toplam **100–500 spawn**. Büyük engagement (çoklu host/AD): 60–80 canlı, binlerce instance. Hepsi `max_agents`, `max_parallel`, `budget_usd`, `wall_clock` limitlerine bağlı.

## 3. Tool katmanı — kaç tool?

**~150 arka plan aracı, ama ajan başına 8–15 tool.** Naptime dersi: "tool arayüzü kalitesi, tool sayısından önemli". Ajanlara ham `nmap` çıktısı yerine yapısal wrapper veririz.

### Tier A — Ajan-facing wrapper'lar (~15, MCP üzerinden)
`terminal` (kalıcı tmux/pty — interaktif araçlar çalışır), `http_client` (ham request + proxy geçmişi), `browser` (Playwright — DOM/screenshot/akış), `python_repl`, `file_ops` (workspace içi), `kg_query`/`kg_write` (knowledge graph), `validator_submit`, `oob_canary` (DNS/HTTP etkileşim token üret+izle), `scope_check`, `cred_vault`, `artifact_store` (hash'li kanıt), `spawn_agent`, `ask_human`, `budget_status`

### Tier B — Kali araç seti (sandbox imajında ~120 araç, terminal üzerinden)
Recon: `nmap masscan naabu amass subfinder dnsx httpx katana gau waybackurls arjun kiterunner tlsx`
Web: `ffuf feroxbuster nuclei nikto dalfox zaproxy wpscan sqlmap commix tplmap jwt-tool`
Ağ/AD: `netexec impacket-* responder mitm6 bloodhound certipy enum4linux-ng evil-winrm`
Exploit/C2: `msfconsole sliver-client (RoE'ye bağlı) searchsploit`
Post: `linpeas winpeas pspy`
Reverse/Forensic: `gdb+pwndbg ghidra-headless radare2 binwalk exiftool volatility3`
Secret/SAST: `trufflehog gitleaks semgrep trivy grype checkov`
Cloud: `prowler scout-suite pacu`
Traffic: `caido-cli mitmproxy`

### Tier C — Custom yazacağımız araçlar
- `oob-server`: interactsh-benzeri kendi OOB dinleme servisi (blind SSRF/XSS/XXE için zorunlu)
- `validator-kit`: sınıf başına deterministik doğrulayıcı kütüphanesi
- `endpoint-inferrer`: framework tahminine göre "şu endpoint'ler var olmalı" (XBOW'un 15→530 numarası)
- `poc-compiler`: bulguyu tek komutta tekrar koşan script'e derler

## 4. Model'i "cyber" yapma stratejisi — 6 katman

**Katman 1 — Role-bazlı model routing (mixture):** Coordinator'a frontier model; solver'a güçlü orta model; varyasyon üretimi/özetlemeye ucuz model. LiteLLM-benzeri router, model başına fallback. Maliyet XBOW'un "thousands of agents" maliyetinin altında kalır.

**Katman 2 — Güvenlik-uzmanı açık modeller:** Cisco **Foundation-Sec-8B / -Reasoning** (Llama-3.1 tabanı, CVE/CWE/ATT&CK/threat-intel üzerine pre-train) → triage, ATT&CK mapping, severity, detection yazımı gibi domain-dil işlerinde lokal çalışır. **WhiteRabbitNeo/DeepHat** payload üretiminde denenebilir. Bunlar frontier modeli *destekler*, yerine geçmez (henüz).

**Katman 3 — Knowledge packs (context engineering, en büyük kısa vadeli kazanç):**
- Solver rolü başına playbook: OWASP WSTG/ASVS, PTES, ATT&CK, CAPEC teknik ağaçları
- Tool cheat-sheet'leri (doğru flag, yaygın tuzaklar)
- RAG indeksi: exploit-db, GHSA/NVD, HackTricks, PayloadsAllTheThings, CTF writeup'ları — solver görev başında ilgili dilimi çeker
- Few-shot exploit pattern kütüphanesi (doğrulanmış geçmiş bulgulardan)

**Katman 4 — Reasoning scaffold'ları:**
- Görev başına hipotez ağacı (PentestGPT task-tree'nin modern hali) — "denenecek teori → beklenen gözlem → sonuç"
- Plan→Act→Observe→Reflect döngüsü + `critic` ajanın itirazı
- **Sampling + verify** (Big Sleep): kritik görevlerde n=3–5 paralel solver farklı yaklaşımla dener, validator kazananı seçer; ensemble disagreement güven skoru üretir
- Refusal-avoidance + scope-bound prompt seti (Strix dersi: yetkili işi reddetmesin, scope dışına çıkmasın)

**Katman 5 — Uzun-ufuk hafıza:**
- Engagement **knowledge graph**: asset→endpoint→param→teknoloji→denenen-teknik→sonuç→bulgu→kanıt. Solver'lar rastgele değil, graf'tan eksikleri okuyup çalışır (tekrar taramayı önler — XBOW'un paylaşılan proxy history'sinin yapısal hali)
- Episodic hafıza: "bu endpoint'te SQLi denendi, WAF X engelledi" — emekli ajanın bilgisi kaybolmaz
- Summarizer + context compaction (EnIGMA)

**Katman 6 — Kendi modelimiz (v3+, asıl "aşırı gelişmiş" kısım):**
- Doğrulanmış engagement trace'lerini topla → SFT ile `aegis-sec` modeli eğit
- Benchmark gym ortamlarında RL (CyberGym tarzı: PoC pre-patch çalışıp post-patch çalışmazsa ödül) — ölçülebilir cyber yetenek kazandırma döngüsü
- Başlangıçta Foundation-Sec-8B tabanlı LoRA gerçekçi hedef

## 5. BYOK — kullanıcı kendi sağlayıcısını getirir

**Evet, istediği modeli kullanır.** Çekirdek model-agnostik bir **LLM Gateway** katmanı üzerinde çalışır:

- Desteklenen sağlayıcılar: OpenAI, Anthropic, Gemini, xAI, OpenRouter, Azure, AWS Bedrock, Groq, DeepSeek, Mistral + **herhangi bir OpenAI-compatible endpoint** (Ollama, vLLM, LM Studio, llama.cpp) → air-gapped lokal kullanım dahil.
- Anahtar yönetimi: env var, `aegis config`, OS keyring veya secret backend; repo'ya asla yazılmaz, log'lara düşmez.
- **Rol başına model ataması** (`models.yaml`):
```yaml
coordinator: anthropic/claude-opus-4.5   # en güçlü akıl yürütme
solver:      openai/gpt-5.3-codex        # ana saldırı modeli
payload:     ollama/whiterabbitneo-70b   # lokal payload modeli
triage:      ollama/foundation-sec-8b    # lokal uzman model
summarizer:  groq/llama-3.3-70b          # ucuz+hızlı
```
- Router: istek başına retry/fallback zinciri, rate-limit saygısı, token bütçesi takibi (`budget_usd` dururda engagement'ı keser), structured output/tool-call normalizasyonu (sağlayıcı farklarını soyutlar).
- Model profili metadata'sı: context boyu, tool-call desteği, reasoning modu → scaffold buna göre davranır (tool-call'suz modelde text-parse modu, HackingBuddyGPT'nin iki modlu yaklaşımı).

## 5b. Dil: Rust (onaylı tercih)

Kullanıcı tercihi: **Rust çekirdek**. Değerlendirme:
- ✅ Uygun çünkü: ağır iş (nmap, browser, exploit) zaten sandbox konteynerinde çalışır; çekirdek sadece orkestrasyon + API çağrısı + KG + validator. Tek binary dağıtım (`aegis` = 1 dosya), düşük RAM (çoğu kullanıcıda Docker zaten yer kaplıyor), tokio async ile yüzlerce paralel ajan, bellek güvenliği (bir güvenlik aracı için önemli sinyal).
- Ekosistem durumu: resmi `rmcp` (Rust MCP SDK) var; LLM client'ları için `async-openai`/kendi router'ımız; Playwright yerine `chromiumoxide` veya sandbox içinde Node/Python browser servisi.
- **Hibrit sınır çizgisi:** saf Rust çekirdek; Python sadece iki yerde — (a) `aegis-bench` benchmark adapter'ları (akademik benchmark'lar Python), (b) `aegis-ml` fine-tune/RL pipeline (v3+, ayrı workspace). Bunlar `cargo` yerine `uv`/pip ile yönetilir, çekirdek onlara gRPC/socket ile konuşur.
- Validator'lar Rust'ta yazılır ama **kullanıcı validator'ları WASM plugin** olarak ekleyebilir → topluluk katkısı sandbox'lı çalışır.

## 5c. Skor beklentisi — harness modele ne katar? (dürüst tahmin)

Araştırma verisi:
- EnIGMA (interactive tools): NYU CTF'de önceki ajanların **3 katından fazla** (13.5% vs ~4%).
- NYU CTF Bench paper: iyi tool-harness'a sahip GPT-4, aynı modelin toolsuz halini katlar.
- XBOW: aynı sınıf modelin scannersız/iş akışsız haline karşı gerçek engagement'ta anlamlı fark; validator katmanı precision'ı ~%100'e çeker.
- CVE-Bench: en iyi ajan ~%13 → gerçek dünya hâlâ zor; abartılı vaat verilmez.

**Gerçekçi aralıklar** (aynı model, benchmark'a göre değişir):
- CTF/lab görevlerinde çözüm oranı: toolsuz/mütevazı harness'a göre **2–5x**.
- False positive: deterministik validator ile **~0** (XBOW standardı).
- Katkı sırası: interaktif araçlar ≫ sampling (pass@5 ≈ 1.5–2x pass@1) > coordinator planlama (çok-adımlı görevlerde) > knowledge packs/RAG > ensemble.
- **Sınır:** model yeteneği tavandır — harness zayıf modeli elit yapmaz, iyi modelin potansiyelini açığa çıkarır. Frontier model + iyi harness > uzman küçük model + aynı harness (şimdilik). Lokal 70B sınıfı modelle beklenen seviye: orta-zor CTF'lerde sınırlı; kullanıcıya bunu dürüstçe söyleyeceğiz.

## 6. Uçtan uca akış (web engagement örneği)

```
aegis init → scope.yaml (hedefler, RoE, yasaklar, bütçe, yetki beyanı)
aegis run --mode red
  1. Coordinator scope'u parse eder → OPPLAN
  2. Egress proxy allowlist'e scope yazılır (ağ seviyesi)
  3. Discovery ajanları → knowledge graph dolar (harita)
  4. Coordinator graph'taki test edilmemiş yüzeyden görev üretir
  5. Solver spawn (taze context) → hipotez → araçlar → aday bulgu
  6. critic itiraz eder/destekler → validator_submit
  7. Validator (kod) kanıtı üretir/tekrarlar → VERIFIED | REJECTED
  8. KG güncellenir, döngü bütçe/bitene dek sürer
  9. report-writer + repro-qa → PoC'li rapor (MD/PDF/SARIF)
aegis run --mode blue → patch öner → retest → detection kuralı → replay
```

## 7. Repo taslağı (Rust workspace)

```
aegis/
  crates/
    aegis-core/       # agent loop, coordinator, task graph, budget, debrief
    aegis-gateway/    # LLM router: OpenAI/Anthropic/compatible endpoints, retry, quota
    aegis-mcp/        # rmcp tabanlı tool server hostu
    aegis-tools/      # terminal(tmux), http, browser, KG, oob, scope_check wrapper'ları
    aegis-sandbox/    # docker | gvisor | firecracker backend trait + impl
    aegis-scope/      # scope.yaml şeması, egress proxy (Squid) yöneticisi
    aegis-validate/   # deterministik validator'lar + WASM plugin hostu
    aegis-kg/         # knowledge graph (sqlite+sled; opsiyonel neo4j)
    aegis-knowledge/  # playbook'lar, RAG indeksleri
    aegis-blue/       # patch, retest, detection-eng, replay
    aegis-evidence/   # artefakt store, hash, rapor (MD/PDF/SARIF)
    aegis-cli/        # clap CLI + ratatui TUI + web dashboard (axum+ws)
    aegis-bench/      # benchmark runner (Python adapter'lara socket)
  agents/             # ajan tanımları (.yaml + .jinja prompt) — kullanıcı düzenler
  playbooks/          # OWASP/ATT&CK/CAPEC knowledge pack'leri
  sidecars/
    bench-adapters/   # Python: Cybench/AutoPenBench/CyberGym köprüsü
    aegis-ml/         # Python: aegis-sec fine-tune pipeline (v3+)
  docker/             # kali-aegis imajı, egress proxy, oob-server
```

Lisans Apache-2.0. Tek binary: `cargo install aegis` → `aegis run`.

## 7b. Kabiliyet tavanı — "çok daha iyi" yapmanın 9 kolu (yeni araştırma)

Araştırma turu 2: ChainPen (PentestEval 346 görevde %52.3 E2E vs VulnBot %6, PentestGPT %39), MulVAL neuro-symbolic attack graph'ları, MITRE Caldera, OSS-Fuzz LLM harness synthesis, RL-CyberBench self-play arena, coevolutionary security literatürü. Buradan çıkan yükseltmeler:

**1. Probabilistic Attack Graph (PAG) — coordinator'ın beyni.** Task kuyruğu yerine: her saldırı adımı = DAG düğümü (önkoşul fact'ler → aksiyon → kazanılan fact'ler), kenarlarda başarı olasılığı + maliyet. Coordinator expected-utility ile sıradaki kenarı seçer. ChainPen'in %52 vs %6 farkının ana kaynağı bu + kalıcı KG. MulVAL/Datalog ile **denetlenebilir** sembolik yol çıkarımı da ekleriz — LLM'in sezgisini sembolik planlamayla birleştirir (neuro-symbolic). Bulgu sayısı değil, **zincir derinliği** burada kazanılır.

**2. Selective Memory / context-rot önlemi.** ChainPen verisi: başarısızlıkların %42'si context kaybından. Çözüm: ajanlar arası tek paylaşılan yapı = KG (lossy summary değil); episodic memory; her fact'ın provenance'i.

**3. Caldera/Atomic Red Team köprüsü — anında TTP kütüphanesi.** Tekerleği yeniden icat etmeyiz: Caldera'nın "ability + fact + planner" modelini benimser, Stockpile + Atomic Red Team'in yüzlerce doğrulanmış TTP'sini ability corpus olarak import ederiz → purple modda blue doğrulama kapsamı 1. günde devasa.

**4. LLM-guided fuzzing (derin kod modu).** Kaynak kodlu hedeflerde OSS-Fuzz deseni: Fuzz Introspector → LLM'e harness yazdır → derle → coverage feedback → tekrar. Google bununla 26+ gerçek CVE buldu (OpenSSL dahil). `aegis run --deep` modu bunu koşturur; crash triage → PoC → validator. OSS-CRS bridge'iyle ensemble fuzzing.

**5. Self-play arena (v3+, asıl roket).** RL-CyberBench deseni: attacker vs defender ajan aynı Docker/containerlab arena'sında sırayla saldırır/savunur; **deterministik judge** (LLM judge YOK → reward hack yok); trace'ler → SFT+GRPO → `aegis-sec`. Coevolution: her iki politika birbirini geliştirir → harness'ın modeli zamanla rakip modelleri geçer. Bu, "modelleri cyber olarak aşırı artırma" sorusunun gerçek cevabı.

**6. Aegis MCP sunucusu olarak.** `aegis serve` → harness'ın kendisi MCP tool'u olur: Claude Code, Cursor, başka ajanlar onu çağırır (`pentest(target)`, `validate(poc)`, `blue_retest(finding)`). Kimsede yok; harness'ı ekosistemin altyapısı yapar.

**7. Dağıtık controller (XBOW ölçeği).** Tek makine modu + `aegis worker` modu: controller NATS/Redis kuyruğu üzerinden yüzlerce makinedeki worker'a solver dağıtır → binlerce paralel ajan, bulut ölçeği.

**8. Deneyim volanını (experience flywheel).** Doğrulanmış bulgular otomatik pattern-library'e düşer → sonraki engagement'ta few-shot olarak enjekte → sistem her koşuda öğrenir (opt-in, lokal). Cross-engagement hafıza.

**9. Sürekli mod + CI.** `aegis watch` → repo/URL değişiminde delta-pentest (XBOW'un "re-test every fix" özelliğinin açık hali); GitHub Action her PR'da yüzey diff'i test eder.

### Domain pack'leri (aşırı genişlik)
Her domain bir "pack": ajan tanımları + tool seti + validator'lar + playbook'lar.
- `web` (MVP), `api`, `network`/`ad` (Caldera abilities ile), `cloud` (AWS/Azure/GCP IAM misconfig + attack paths), `binary` (fuzz harness + pwn), `mobile` (Android/iOS), `smart-contract`, `llm-target` (PyRIT bridge — AI uygulamasını test et), `supply-chain` (SBOM+typosquat+CI), `saas-config` (M365/Entra/Google Workspace posture), `iot` (emüle firmware).

### CLI komut seti (onaylandı: CLI-first)
```
aegis init                 # scope + RoE sihirbazı
aegis run --mode red|blue|purple [--deep] [--hitl] [--budget $]
aegis copilot              # insan+coordinator ortak sürüş (interaktif)
aegis serve [--mcp]        # API/MCP sunucusu — IDE/agent'lara harness'ı aç
aegis worker --join <ctrl> # dağıtık worker
aegis bench --suite X      # benchmark runner
aegis replay <finding>     # PoC'yi tekrar koştur
aegis report / export      # MD/PDF/SARIF/bug-bounty formatı
aegis pack list/install    # domain pack + plugin marketplace
aegis arena                # self-play eğitim alanı (v3)
aegis watch                # sürekli delta-pentest
```



| Metrik | Hedef |
|---|---|
| AutoPenBench / NYU CTF / Cybench skoru | Strix/Decepticon'un public skorlarını geç (public benchmark = güven) |
| False positive oranı | XBOW standardı: ~0 (validator'sız bulgu rapora girmez) |
| Uçtan uca engagement | Tek komutla scope→rapor, insan müdahalesiz (HITL opsiyonel) |
| Blue loop | Bulgu→patch→retest→kural pipeline'ı çalışır (kimsede yok) |
| Scope güvenliği | Egress allowlist + mount koruması + audit imzası |

## 9. Yol haritası

- **Faz 0**: Spike — Strix/Decepticon/OSS-CRS/Caldera kur, desenleri doğrula, ADR'ler.
- **Faz 1 (MVP)**: CLI-first web pentest: coordinator + PAG-lite + discovery(3) + solver(5) + validator-kit(enjeksiyon/XSS/SSRF) + Docker sandbox + egress proxy + KG-lite + TUI. Ölçüt: AutoPenBench alt kümesi.
- **Faz 2**: Blue loop + PAG tam (expected-utility) + episodic memory + sampling + solver 18 + domain pack: api, network.
- **Faz 3**: `aegis serve --mcp` + `aegis worker` (dağıtık) + LLM-guided fuzzing/deep mod + Caldera/Atomic ability import + purple mod + benchmark leaderboard + CI action.
- **Faz 4**: Domain pack'ler (ad/cloud/binary/mobile/llm-target) + self-play arena + `aegis-sec` LoRA/RL + plugin marketplace.

## 10. Kalan kararlar

1. Stack: **Rust çekirdek** ✅ (kullanıcı onayladı) + Python sadece sidecar'larda
2. Agent loop: **kendi loop'umuz + MCP (rmcp)** 
3. Sandbox: **Docker varsayılan, gVisor opsiyonu, Firecracker cloud profili**
4. İsim: "Aegis" geçici — beğeniyor musun, başka ad?
5. Lisans: Apache-2.0
6. Repo: yeni repo — GitHub'da hangi org/hesap altında? (create card gönderebilirim)
