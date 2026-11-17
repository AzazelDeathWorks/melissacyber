# melissacyber — derin kod denetimi (v2, kapsamlı)

Kapsam: ~5.000 satır, 12 crate'in tamamı satır satır okundu. Canlı test yok.
Severities: [C] kritik (sistemin iddiasını bozar / güvenlik deliği) · [H] yüksek · [M] orta · [L] düşük.

## 0. Acı gerçek — rakip tablosu (dürüst durum)

| Kabiliyet | XBOW | Strix | Decepticon | melissacyber (bugün) |
|---|---|---|---|---|
| Deterministik validator | ✅ ~0 FP | ⚠️ kısmi | ❌ | ✅ var, ama 6 sınıf + GET-only |
| Coordinator re-planning | ✅ LLM, sürekli | ⚠️ | ❌ | ❌ tek atış, bulgudan yeni görev çıkmaz |
| Tarayıcı ajanı (DOM/SPA) | ✅ | ✅ | kısmi | ❌ yok — SPA hedef görünmez |
| Auth/session modeli | ✅ | ✅ | kısmi | ❌ login tool yok, creds yok, cookie yok |
| HTTP yüzeyi | tam | tam | tam | ❌ sadece query-param GET |
| Persistent shell (tmux) | n/a | ✅ | ✅ | ❌ her `terminal` çağrısı yeni `sh -lc` |
| Ağ katmanı (nmap/port/servis) | ✅ | ✅ | ✅ | ❌ HTTP-only |
| Prompt-injection koruması | ✅ | kısmi | ❌ | ❌ hedef çıktısı doğrudan context'e |
| Scope enforcement | prompt | prompt | ❌ | ✅ ağ katmanı (docker'da) — bizim tek üstünlüğümüz |
| Resume/checkpoint | ✅ | kısmi | ❌ | ❌ crash = her şey gider |
| Bütçe/rate limit | ✅ | kısmi | ❌ | ❌ parse var, uygulama yok |
| Knowledge packs | kendi | kısmi | ❌ | ⚠️ dosyaları var, koda bağlı değil |

Sonuç: validator iskeleti + ağ-scope tasarımı gerçekten doğru yön; ama capability yüzeyi rakiplerin ~%20'si. Aşağıdaki P0'lar kapanmadan "XBOW sınıfı" iddiası erken.

## 1. Kritik bug'lar — iddiaları bozanlar

### B1 [C] Rapor, kanıtı rapora koymuyor
`run_pipeline.rs:338-346`: `render_markdown` 5-tuple `(title, sev, class, repro, evidence)` beklerken biz `(title, sev, class, evidence_json, "")` gönderiyoruz. Sonuç: `**Proof:**` alanına ham evidence JSON basılıyor, altındaki `json` bloğu **boş**, ve validator'ın ürettiği reproduction cümlesi (`GET /x?q -> SLEEP(3) delayed 3015ms`) **hiçbir yere yazılmıyor**. "Her bulgu tekrar-koşulabilir PoC içerir" vaadi raporda yok.
Fix: `(f.title, sev, class, reproduction, evidence_json)` sırasıyla geç — Verdict::Verified içindeki reproduction'ı taşı.

### B2 [C] CmdInjection validator'ında false-positive yolu
`cmd.rs`: canary `;echo aegcmdXXX` gönderilip `body.contains(marker)` bakılıyor. Hedef, girdiyi verbatim yansıtan bir hata sayfası döndürürse (yaygın), marker hiç çalıştırılmadan body'de görünür → **"verified" ama hiçbir şey çalışmadı**. 0-FP vaadini kıran tek validator deliği.
Fix: payload'da marker'ı parçala (`;printf 'aeg%s' 'cmdXXX'` → response'da `aegcmdXXX` ara; ya da `;expr 691*689` → `475906` ara — SSTI deseni).

### B3 [C] Redirect ile scope bypass (hem HttpTool hem ProbeClient)
reqwest default'u 10 redirect takip eder; allowlist sadece **ilk** host'a bakıyor. İzinli hedef `302 → http://169.254.169.254/...` veya out-of-scope domain'e yönlendirirse probe/solver sessizce takip eder. Validator'ların kendi scope'u deliniyor.
Fix: `reqwest::redirect::Policy::none()` + redirect header'larını allowlist'ten geçerek elle takip.

### B4 [C] Sandbox sızıntısı + sessiz solver ölümü
`run_pipeline.rs:330` — `run_engagement(...).await?` hata verirse `backend.destroy()` hiç çağrılmaz: container + network sızar. Ayrıca `engagement.rs:271` `let _ = h.await` — solver'ın döndürdüğü `Err` (auth fail, 429, context overflow) tamamen yutulur, log'a bile düşmez; sonuç sayacında "ölü solver" yok.
Fix: `scopeguard`/drop ile destroy; handle sonucunu match'le, error sayısını EngagementResult'a ekle.

### B5 [C] Retry/backoff yok — 429'da sürü ölür
16 paralel solver tek API key'i paylaşır; herhangi bir rate-limit → `ProviderError::RateLimited` → solver ölür (ve B4 yüzünden sessizce). Gerçek koşularda solver'ların anlamlı kısmı kaybedilir.
Fix: exponential-backoff retry (429/5xx) + jitter + provider başına global concurrency limiter.

### B6 [H] Context patlaması — terminal çıktısı sınırsız
`TerminalTool` output'unu olduğu gibi context'e basıyor (http 64KB'de kırpıyor). `sqlmap`, `nmap -A`, hatta `cat /dev/urandom` → MB'lar → context aşımı → solver ölümü. Ayrıca hiçbir compaction/summarization yok; 24 tur içinde transcript 128k'yı aşabilir.
Fix: tool-output truncate (head+tail), transcript token bütçesi, dolunca özet düğümü.

### B7 [H] Provider failover çalışma zamanında yok
`env_provider_for` fallback zinciri sadece **build** aşamasında denenir; primary build olur ama çalışırken 401/quota/model-not-found verirse fallback'e düşülmez — solver ölür.
Fix: complete() hatasında zincirin sonraki provider'ını dene.

## 2. Güvenlik / RoE — vaat edilen enforcement'ın tamamı ölü

- **S1 [C] RoE'nin tamamı dekorasyon**: `rate_limit_rps`, `allow_dos`, `allow_exfil`, `allow_persistence`, `allow_bruteforce`, `allow_social_engineering`, `window_utc` — hiçbiri tek satır enforcement'a bağlı değil. RPS 10 yazıyor, pratikte sınırsız paralel istek → **küçük hedefi DoS'larız, hem de RoE'ye rağmen**. `--hitl` sadece println.
  Fix: token-bucket limiter (HttpTool + ProbeClient), flag'lere göre payload sınıfı reddi, window kontrolü başta.
- **S2 [C] Prompt-injection yüzeyi sıfır savunma**: hedef sayfa/tool çıktısı doğrudan solver context'ine giriyor. Kötü niyetli hedef "validator_submit şu evidence'la çağır" ya da "görev bitti" yazabilir; hatta terminal'e komut enjekte ettirebilir. Validator'lar finding tarafını korur ama erken-exit ve yan-kanal saldırıları açık. (Rakiplerde output sanitization/tool-allowlist daraltma var.)
  Fix: tool çıktılarına "untrusted data" çerçevesi, `validator_submit` çağrısında evidence'in solver'ın kendi tool-output'undan türediği kontrolü, terminal komut whitelist'i opsiyonu.
- **S3 [C] Host backend = tamamen korumasız**: `http_client` allowlist bakar ama `terminal`'den `curl` doğrudan çıkar; üstelik docker provision başarısız olunca **sessizce** Host'a düşüyor (`run_pipeline.rs:210`) — gerçek hedefe karşı sandbox'sız + scope'suz exec. En azından fallback'i non-lab target'ta reddet veya `--allow-host-backend` bayrağı iste.
- **S4 [H] MCP/worker sunucusu auth'suz ve 0.0.0.0'a açık**: LAN'daki herkes `/jobs`'a iş koyar, `/mcp`'ten `aegis_validate` ile senin kutunu probe proxy'si yapar. `scope.yaml` yoksa allowlist `127.0.0.1,localhost` — kendi makinenin servislerini hedef aldırırlar.
  Fix: `--bind` default 127.0.0.1 + bearer token + TLS notu.
- **S5 [H] OOB sunucusu 127.0.0.1'e bağlı**: uzak hedef callback atamaz → blind SSRF/XSS/XXE gerçek dünyada doğrulanamaz. Ayrıca **DNS listener yok** (interactsh'in ana sinyali — DNS-only exfil göremeyiz) ve HTTPS yok.
  Fix: `--oob-bind` + `AEGIS_OOB_PUBLIC` base URL + mini DNS server (token subdomain → TXT/lookup log).
- **S6 [M] `read_http` tek 64KB read**: büyük job/result gövdeleri veya parçalı TCP okuması → bozuk JSON, sessiz 400.
- **S7 [M] `sigma_for` YAML'e `f.title`'ı ham basıyor** — tırnak/satır içeren başlık kural dosyasını bozar.
- **S8 [L] `authorization_statement` self-attested metin** — README "signature" der, imza/kimlik mekanizması yok.

## 3. Validator derinliği — sınıf sınıf analiz

Genel yapı doğru (baseline→inject→diff→verify). Ama:

- **V1 [C] Her şey GET + query-param**: `ProbeClient` sadece `.get().query()`. POST/PUT/JSON-body/form/header/cookie/path-param test edilemez **ne solver hedefi olarak ne validator olarak**. Gerçek API'lerde yüzeyin yarısından fazlası kapsam dışı. Login formları (POST) bu yüzden bypass'a takıldı.
  Fix: `ProbeClient::send(method, url, query, headers, body)` + evidence'e `in` alanı (query|body|header|path).
- **V2 [H] SQLi boolean-diff JSON'da ölü**: `jaccard` whitespace-token bazlı — minify JSON'da tek token → 0 veya 1. API hedeflerinde boolean-blind SQLi sessizce reddedilir.
  Fix: char-3gram Dice benzerliği veya normalized-diff.
- **V3 [H] Timing tek örnek**: `SLEEP(0)` vs `SLEEP(3)` birer ölçüm — jitter'da flaky iki yönde. Median ≥2.
- **V4 [H] SSRF OOB'da request body/header yakalanmıyor**: sunucu sadece ilk satırı parse eder (8KB); exfil içeriği görünmez — "veri sızdı" ispatı yok, sadece "bağlandı" var.
- **V5 [M] XSS sadece reflected-GET**: DOM, stored, POST ve JS-context ayrımı yok. Tarayıcı olmadan DOM-XSS imkansız — tarayıcı tool'u ile birlikte düşünülmeli.
- **V6 [M] FilePath sigs yetersiz**: `daemon:` gibi zayıf imzalar rastlantısal eşleşebilir; `/etc/passwd`-varyantları dışında hedef dosya yok (hedefin kendi config'ini okumak daha iyi ispat — solver'ın KG'den öğrendiği dosya adı).
- **V7 [M] ReplayValidator GET-only + `request.method`/`body` yok**: POST sink'leri replay edilemez.
- **V8 [M] Class-coverage 7/20**: `Authn, AuthzIdor, SessionJwt, Deserialization, Xxe, Smuggling, Cors, Race, Crypto, Nosqli, Crash` için validator yok → bu sınıflar "no validator — dropped" ile sessizce atılıyor. Kullanıcı nelerin hiç denenemediğini bilmiyor.
  Fix: her desteklenmeyen sınıf için generic signal validator'lar (authn=neg-control+state-flip, cors=origin-reflection check, jwt=alg-none/none-claim replay, info-disclosure=secret-pattern regex) + raporda "test edilemedi" listesi.
- **V9 [M] evidence shape tutarsızlığı**: `evidence_headers` sadece flat `evidence.headers` okur; `Replay` ikisini de kabul eder. Solver'a yazılı şema verilmemesiyle birleşince doğru bulgular şekil yüzünden düşüyor (canlıda gördük).
  Fix: `validator_contract()`'a sınıf-başına zorunlu alanlar + tek ortak `request:{method,url,headers,body,params}` şeması.

## 4. Mimari — tasarlanan vs çalışan

- **A1 [C] Coordinator tek atış**: discovery→jobs→solver→intake doğrusal; **verified bulgu yeni objective üretmiyor**. Kimlik bilgisi bulan solver'ın çıktısı başka hedefe taşınmaz; chain kompozisyonu ancak tek solver'ın context'inde tesadüfen olur. XBOW'un asıl gücü bu döngü — bizde yok.
  Fix: intake Verified → KG'ye fact node + coordinator "wave 2" (creds→login, secret→endpoint, ssti→rce denemesi).
- **A2 [C] Knowledge packs ölü**: `packs/*.yaml` 11 domain tanımlı ama hiçbir solver prompt'una girmiyor; `KnowledgePack` sadece `pack list`'te basılıyor. Ajanların sınıf-özel playbook'u yok — hepsi aynı jenerik objective alıyor.
- **A3 [H] `spawn_agent` ölü kod**: role kısıtı `["coordinator"]`, ama coordinator bir *ajan* değil (kod). Solvers spawn edemez → deferred-spawn bloğu hiç çalışmıyor.
- **A4 [H] Agent spec'leri ölü**: `spec_loader` + `agents/*.yaml` hiçbir yerde okunmuyor — `max_turns`, tool allowlist, model_role'lar dosyada tanımlı ama hardcoded `solver_turns: 24` geçiyor.
- **A5 [H] `aegis worker` stub**: `{"status":"done"}` postalıyor, hiçbir şey çalıştırmıyor — dağıtık mod iddiası gerçek değil.
- **A6 [H] `aegis arena` hardcoded**: 4 sabit saldırı + sahte responder — self-play değil, deterministik demo. Trace'ler bu haliyle SFT verisi olamaz.
- **A7 [M] Critic kırılgan**: `contains("reject") && !contains("pass")` — "not rejectable" reddeder; "pass-ish but reject" geçer. LLM çağrısı başına maliyet + fail-open. Critic provider yoksa kapı tamamen yok, sessizce.
- **A8 [M] Tek-transcript kaybı**: transcript'ler diske düşmüyor → debug, replay, SFT verisi, "hangi solver ne denedi" denetimi yok.
- **A9 [M] Dedup yok**: aynı (class,path,param) bulgusu rapora tekrar giriyor (canlıda 3× aynı SSRF).
- **A10 [M] Coverage takibi yok**: hangi (endpoint,param,class) test edildi/negatif çıktı bilinmiyor — raporda "test edildi ama temiz" listesi yok; parametresiz endpoint'lere hiç solver gitmiyor (info-disclosure sınıfı da yok).
- **A11 [M] Transcript büyümesi yönetimsiz** (B6 ile akraba) + `max_tokens:8192` hardcoded + stop_reason kontrolü yok.
- **A12 [L] Dead code**: `Engagement`, `Turn`, `Agent` trait, `AgentSpec`, `ReportFormat`, `FindingReport`, `Verdict::Preview`, `graph.frontier()` (hepsini döndürüyor — "untested" semantiği yok), `spec_loader`, `Mode::Deep` yol ayrımı yok (mode label only).

## 5. Tool yüzeyi — 10 araç, eksik temel parçalar

Var: terminal, http_client, scope_check, oob_canary, kg_write/query, validator_submit, spawn_agent(ölü), budget_status, artifact_store.

Yok ve rakiplerde kritik:
- **browser** (Playwright) — SPA crawl, DOM XSS, click-flow → V5 ve discovery için şart
- **persistent shell / tmux session** — `sh -lc` her seferinde sıfırlanır; `cd`, env, `msfconsole`, `sqlmap --wizard` state taşıyamaz. Decepticon'un bütün avantajı bu.
- **login/session tool** — creds store, form auth, cookie jar, token refresh
- **nmap/dns/port-scan** — ağ keşfi yok
- **file_ops in sandbox** (read/write/patch target repo for code targets) — `LocalCode`/`Repository` target kind'ları var ama hiçbir tool dosya okuyamaz → code-review akışı imkansız
- **request_replay** — solver'ın kendi request'ini deterministik saklayıp validator'a vermesi (ReplayValidator'ın hammadde'si)
- **screenshot** — kanıt olarak

Ayrıca: `kg_write` provenance hep `None`; `KgTool` sınırsız veri kabul ediyor (context zehirleme riski); `artifact_store`'a link report'ta yok.

## 6. Ölçek / operasyon

- **O1 [H] findings kanalı 256 + intake sıralı**: SSRF 5sn/başlık → >256 birikimde solver'lar `validator_submit`'te bloklanır. Intake'i semaphore'lu paralel yap.
- **O2 [H] SIGINT graceful shutdown yok**: Ctrl+C → container+network sızar, kısmi rapor/transcript kaybolur.
- **O3 [M] Resume yok**: crash'te engagement baştan başlar (journal/checkpoint lazım — XBOW ölçeğinde şart).
- **O4 [M] Spend `$0.00`**: usd hiç hesaplanmıyor; models.yaml'a `cost_in/out` alanı + hesap.
- **O5 [M] CI workflow kırık**: `scope.ci.yaml` repoda yok → workflow her PR'da `read_to_string` hatası (continue-on-error ile yutuluyor — sessiz kırmızı). `cargo test` adımı da yok — 33 test CI'da koşmuyor.
- **O6 [M] `few_shot` çapraz-engagement sızıntısı**: A hedefinden öğrenilen pattern, B hedefinin solver prompt'una giriyor — gizli kalması gereken engagement verisi prompt'ta dolaşıyor. Opt-in yapılmalı.
- **O7 [L] models.yaml CWD-relative**: başka dizinden çalıştırınca router sessizce kaçırılır → env default'larına düşer.
- **O8 [L] endpoint_tasks KG-check'siz**: solver `evil.com` endpoint yazarsa job üretilir → boşa koşu (allowlist HTTP'de yakalar ama terminal'de host-backende değer).
- **O9 [L] `agents/` dizini, `docs/design.md`'deki vaatlerle kod arasındaki fark**: roadmap olarak kalıyor — README'de "done" gibi görünenler işaretlenmeli.

## 7. Öncelikli yol haritası (kapanma sırası)

**P0 — iddiayı kurtaranlar (1-2 oturum):**
1. B1 rapor-proof bug + rejected-section + dedup + transcript kalıcılığı
2. B3 redirect policy + S3 host-fallback kilidi
3. B5 retry/backoff + B6 output truncation + B4 destroy-leak + solver error sayacı
4. V1 POST/JSON/body desteği (ProbeClient::send + evidence `in` alanı)
5. B2 cmd-validator FP kapatma (arithmetic/split-marker)
6. S1 rate limiter + O4 usd hesabı (budget'ı gerçek yap)

**P1 — rakip paritesi başlangıcı:**
7. A1 ikinci planlama dalgası (verified→yeni objective: creds→login, secret→endpoint)
8. Browser tool (playwright) + DOM-XSS validator
9. Persistent shell (tmux içinde session)
10. Login/auth tool + creds store
11. A2 knowledge packs'i solver prompt'una bağla; A3 spawn'ı solver'a aç (sınırlı)
12. V8 en az 4 generic validator daha (info-disclosure, cors, jwt, authn-state-flip) + "untested coverage" raporu

**P2 — ölçek ve derinlik:**
13. S5 OOB public bind + DNS listener
14. O3 journal/resume; O1 parallel intake; A4 spec'leri wire et
15. V2 JSON-aware diffing; V3 timing medyanı; V4 full request capture
16. A6 gerçek arena (provider-driven); A5 gerçek worker; S4 serve auth
17. network pack (nmap/dns), file_ops, SARIF/HTML report, CVSS skorlama

## 8. Özet cümle

İskelet doğru: scope→discovery→solver→validator→rapor boru hattı çalışıyor ve validator fikri gerçekten slop'u kesiyor. Ama şu an bu bir **"GET-param web lab kanıtlayıcısı"**; XBOW paritesi için eksik olan tek şey polish değil — **POST yüzeyi, tarayıcı, auth, persistent shell, re-planning, coverage ve enforcement**. P0 listesini kapadıktan sonra rakiplerle aynı cümlede anılmaya başlarız; P1 bitince geçeriz.

---

## Implementation status (commit 7a2c9b1)

P0 — all fixed: report repro/rejected section, redirect scope bypass, retry/backoff, rate limiter, POST/form/json/header/path injection via send_value, cmd-validator reflected-canary FP, wall-clock timeout, solver error accounting, non-local host-fallback refusal, MCP Content-Length+auth+bind.

P1 — shipped: re-planning escalation wave, param-less sweeps (InfoDisclosure+Cors), parallel intake, dedup, traces/, journal.jsonl, auth_login+session store, persistent shell, portscan/dns_lookup/web_inspect/file ops, OOB full capture + DNS listener, JWT/CORS/XXE/InfoDisclosure validators, sqli Dice+multi-sample timing, prices->real USD spend, untrusted-output wrapping, real worker, LLM arena attacker, SARIF, CI (cargo test + lab engagement).

P2 — shipped (commit 275e9e6): real headless Chrome `browser` tool (post-JS DOM + link/form/script extraction), `tmux` interactive-session tool (msfconsole/sqlmap REPLs), `--resume` (kg.json + verified_keys restore, discovery skipped), pack hints injected into solver objectives, IP-literal normalization (127.1/hex/octal/::1 bypasses closed), CVSS 3.1 estimates in report, `pack install/new/remove`, host-scoped few-shot (cross-target leak closed). Remaining honest gaps: browser has no steering (single-shot render, no click/fill), tmux needs tmux in the sandbox image (HostBackend fine), resume restores dedup+KG but not in-flight solver state.

## REDCELL spec status (post-G4)
- Policy broker + action classes + kill switch + secrets slots: shipped
- 18 validator classes: shipped (10 → +8 web2 validators)
- Reachability prefilter + second verifier + NeedsRetry/Informational: shipped
- LATS route search (UCB, masking, pivot, decay) + milestones + bounty dual-mode + funnel: shipped
- Exploit-craft (gdb_debug, payload_mutator), meta-tooling (define_tool), reflections, CWE/PDF, runsc/kata tiers: shipped
- Remaining known limits: pgvector recall (jsonl KG), SelfOp prompt mutation, real HITL UI gate (env-driven), browser steering
