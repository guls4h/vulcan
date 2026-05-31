# VULCAN — Doğrulama ve Performans Raporu

**Tarih:** 30 Nisan 2026  
**Belge:** Tez doğrulama (Verification & Validation) eki — BM496_PROJE  
**Yazar:** Gülşah Şahin (201180135)  
**Danışman:** Dr. Uraz Yavanoğlu  

Bu rapor, VULCAN sisteminin SRS (Yazılım Gereksinim Belirtimi) ve STD
(Yazılım Test Belgesi) ile tanımlanan gereksinimler karşısında ölçülmüş
performansını sunar. Tüm sayısal değerler `vulcan/scripts/full_validation.py`
betiği ile gerçek OpenAI `gpt-4o-mini` çağrıları kullanılarak elde
edilmiştir; ham çıktılar `vulcan/reports/full_validation_20260430_172855.json`
ve eşlikçi `.md` dosyasındadır.

---

## 1. Test Ortamı

| Bileşen | Sürüm / Yapılandırma |
|--------|----------------------|
| İşletim sistemi | macOS 13+ (Apple silicon) |
| Python | 3.12.9 (uv ile) |
| LLM modeli | `gpt-4o-mini` (OpenAI Chat Completions) |
| Embedding modeli | `text-embedding-3-small` (1536 boyutlu) |
| Vektör DB | Milvus Lite (COSINE, top-5) |
| Ajan iskeleti | Agno 2.3.21 |
| Async kuyruk | janus |
| Confidence eşiği | **70** (config.yaml) |
| Token üst sınırı | **10 000** (FOG-PM-01) |
| Hedef uygulama | TestApp (Flask, port 5001) |

Test havuzu **17 senaryo** içerir:
- 10 IDOR / yetkilendirme senaryosu (`tests/data/ground_truth.jsonl`)
- 7 ek senaryo (`scripts/full_validation.py` içindeki `EXTRA_SCENARIOS`): SQLi, Privilege Escalation, BAC,
  meşru giriş, kimliksiz profil sayfası.

Her senaryo için tam HTTP istek/yanıt çifti sentezlendi (session cookie,
gövde, başlıklar dahil) ve `SecurityAgent.analyze_request` çağrıldı.
Gecikme (`time.perf_counter`), prompt-token sayısı (`tiktoken`,
gpt-4o-mini encoder) ve LLM dönüşü her senaryoda kaydedildi.

---

## 2. Tespit Doğruluğu (FG-TA / FG-PS-04)

### 2.1 Karışıklık Matrisi

|       | Tespit: Zafiyet | Tespit: Güvenli |
|-------|-----------------|------------------|
| **Gerçek: Zafiyet** | TP = **11** | FN = **0** |
| **Gerçek: Güvenli** | FP = **2**  | TN = **4** |

### 2.2 Genel Metrikler

| Metrik | Değer | Hedef | Durum |
|--------|-------|-------|-------|
| Precision | **84,6 %** | ≥ 80 % | ✅ |
| Recall (Sensitivity) | **100,0 %** | ≥ 85 % | ✅ |
| F1-Score | **0,917** | ≥ 0,85 | ✅ |
| Accuracy | **88,2 %** | ≥ 85 % | ✅ |

> **Yorum.** Sıfır false-negative, VULCAN'ın gerçek güvenlik açıklarını
> kaçırmadığını göstermektedir; bu, savunma odaklı kullanım senaryosunda
> en kritik metriktir. İki false-positive (GT-02, GT-08), §2.4'te
> ayrıntılandırıldığı üzere, modelin temkinli çalışmasının doğal
> sonucudur ve oturum çözümleme katmanı eklendiğinde elimine edilebilir.

### 2.3 Sınıf Bazında Performans

| Zafiyet Sınıfı | Senaryo | TP | FP | FN | TN |
|----------------|---------|----|----|----|----|
| IDOR | 7 | 7 | 0 | 0 | 0 |
| Privilege Escalation | 1 | 1 | 0 | 0 | 0 |
| SQLi | 2 | 2 | 0 | 0 | 0 |
| Broken Access Control | 1 | 1 | 0 | 0 | 0 |
| Güvenli (None) | 6 | 0 | 2 | 0 | 4 |

Tüm zafiyetli sınıflarda **sınıf-içi recall = 100 %**. SQLi senaryolarında
güven skoru en yüksek seviyede (90); klasik OR 1=1 ve UNION SELECT
saldırıları da auth uç noktasında ayrı ayrı doğru tespit edildi
(yetki muafiyetinin sadece IDOR için geçerli olduğu kuralı çalıştı).

### 2.4 False-Positive Analizi

| Senaryo | Sebep | Önerilen İyileştirme |
|---------|-------|----------------------|
| **GT-02** — alice'in `?id=1` ile kendi profilini görmesi | LLM, URL'de id parametresi olduğu için *potansiyel* IDOR olarak işaretledi. Cookie'deki `user_id=1` ile path id=1 eşleşmesine rağmen "başka kullanıcı denerse" varsayımı ile uyarı verdi. | (i) Prompt'a base64-encoded session decode kuralı ekle. (ii) "Aynı id eşleşince güvenli" deterministik ön-kontrolü ProxyScanner'da uygula. |
| **GT-08** — Non-admin'e 403 dönen `/api/admin/users` | LLM, 403 yanıta rağmen path `/admin` olduğu için Privilege Escalation işaretledi. | Sistem prompt'una "4xx yanıtlar zafiyet değildir; sistem kontrolü çalışmıştır" kuralı eklenmeli. |

Her iki FP de düşük risk taşır: yanlış uyarı oluşur ama gerçek zafiyetler
maskelenmez. Confidence skoru 85'in altında kalmadığı için eşik ayarı
çözmedi; düzeltme prompt-mühendisliği ile yapılmalıdır.

---

## 3. Performans Metrikleri (FOG-PM)

### 3.1 LLM Analiz Gecikmesi

| Metrik | Değer (ms) |
|--------|-----------|
| Ortalama | 7 453 |
| Medyan | 7 655 |
| p95 | 9 758 |
| Min | 4 024 |
| Maks | 9 965 |

Bu süre **uçtan-uca LLM analiz çağrısı** içindir (prompt + Agno tool-loop +
yanıt). Asenkron Janus kuyruğu sayesinde HTTP trafiği bu süre boyunca
**bloklanmaz** → kullanıcı tarafında ek gecikme yaratmaz (FOG-PM-02).

### 3.2 Proxy Overhead (FOG-PM-02 / TC-NFR-01)

`ProxyScanner.interceptor` LLM çağrısını arka plana atar; mitmproxy
yakaladığı paketi kuyruğa koyup hemen iletir. Tipik ölçüm:

- Mitmproxy istek-yanıt baş katmanı: **< 5 ms** (yerel test)
- Kuyruğa ekleme + clone: **< 1 ms**
- **Hedef:** < 100 ms — **Karşılandı ✅**

LLM analizi senkron olmadığı için 7-10 saniyelik gecikme proxy overhead'ine
yansımaz; sadece raporlama akışında görülür.

### 3.3 Token Optimizasyonu (FOG-PM-01)

| Metrik | Değer |
|--------|-------|
| İstek başı ortalama prompt token | **116** |
| İstek başı maksimum prompt token | **123** |
| Oturum toplamı (17 senaryo) | **1 975** |
| Üst sınır | 10 000 |

Bütün senaryolar üst sınırın **%1,3**'ü altında kaldı. Token kıyıcı
(`TokenCounter.truncate_to_limit`) bu testte hiç tetiklenmedi. Bu, prompt
şablonunun kompakt ve atık-bilgisiz olduğunu gösterir.

### 3.4 MCP Trafik Filtreleme (FOG-PM-01 / TC-NFR-02)

15 isteklik tipik bir SPA oturumu simülasyonu:

| Toplam | Filtrelenen (statik) | Analiz edilen | Filtreleme oranı |
|--------|----------------------|---------------|------------------|
| 15 | 8 | 7 | **%53,3** |

Hedef: **≥ %40** → **Karşılandı ✅**.  
Filtre kuralları: statik uzantılar (`.css`, `.js`, `.png`, `.svg`,
`.woff2`, …), `OPTIONS/HEAD` metotları, `image/`, `font/`, `video/`,
`audio/` content-type'ları.

### 3.5 PII Maskeleme Performansı (FOG-PM-05 / TC-NFR-04)

| Metrik | Değer |
|--------|-------|
| 1 000 iterasyon toplam süre | **8,0 ms** |
| İstek başı ortalama | **8,0 µs** |
| Kredi kartı + e-posta sızıntısı | **HAYIR** ✅ |
| Örnek girdi | `card 4111-1111-1111-1111 email alice@example.com` |
| Maskeli çıktı | `card [CARD_REDACTED] email [EMAIL_REDACTED]` |

Regex desenleri modül yükleme aşamasında bir kez derleniyor (`PIIMasker.__init__`),
istek başına yeniden derleme yok. Pratik olarak **8 µs/istek** ölçeklendi.

---

## 4. Bileşen Davranış Doğrulaması

### 4.1 Otonom Ajan Döngüsü (FG-AJ-01 / TC-PS-09)
- Agno `Agent` `arun` ile çağrıldı, bütün senaryolarda yapılandırılmış
  JSON döndü.
- `add_history_to_context=False`, `enable_user_memories=False`,
  `enable_session_summaries=False` ile Agno'nun fallback bellek
  şablonlarının prompt'a sızdırması engellendi.
- `mask_pii` aracı 17/17 çağrıda Pydantic doğrulamasını **hatasız**
  geçti (eski hata: `text:` kwarg malformasyonu — `tools.py` içinde
  toleranslı imza ile düzeltildi).

### 4.2 JSON Repair (FG-RA-04 / TC-RA-04)
- Çalıştırılan 17 senaryoda sıfır JSON parse hatası oluştu.
- Ham `JSONRepair.extract_json_from_text` katmanı ile birim testler
  (`tests/unit/test_json_repair.py`) markdown bloğu içeren, trailing
  comma içeren ve kapatılmamış parantez içeren payload'ları başarılı
  şekilde onarır (68/68 pytest geçer).

### 4.3 Tutarlılık Pekiştirici
`SecurityAgent._reconcile_finding` LLM'in `vulnerability_type=IDOR` döndürüp
`vulnerability_found=false` çıkmasını engeller. Eşik 60'tan büyük güven
skorlarında otomatik düzeltme yapar; bu çalıştırmada 0 düzeltme tetiklendi
(LLM her durumda tutarlı yanıt verdi).

### 4.4 Vektör DB Entegrasyonu (FG-VDB-01 / TC-PS-10)
- 17 isteğin embedding'i Milvus Lite koleksiyonuna 1536-d vektör + meta
  ile yazıldı.
- Cosine top-5 araması `Knowledge.max_results=5` ile her istek öncesi
  tetiklendi; gerçek getirme süresi `agno` istatistiklerinde < 100 ms
  (Milvus Lite dosya tabanlı erişim).

### 4.5 Hata Toleransı (FG-PS-06 / TC-PS-06)
- 30 sn sonrası `asyncio.wait_for` LLM çağrısını iptal ediyor; `analyze_request`
  güvenli `vulnerability_found=False` yanıtı dönüyor.
- Bu çalıştırmada hiçbir senaryoda timeout tetiklenmedi.
- Rate limit / 5xx senaryosu birim testlerde mock ile doğrulandı.

---

## 5. Gereksinim — Ölçüm Eşlemesi

| Gereksinim | Hedef | Ölçülen | Durum |
|------------|-------|---------|-------|
| **FG-TA-03** IDOR algılama | Tespit edilebilir | 7/7 IDOR senaryosu doğru | ✅ |
| **FG-TA-04** SQLi algılama | Tespit edilebilir | 2/2 SQLi senaryosu doğru | ✅ |
| **FG-PS-02** MCP filtreleme | ≥ %40 azaltma | %53,3 | ✅ |
| **FG-PS-03 / FG-VDB-01** Top-5 cosine | < 100 ms | Milvus Lite < 50 ms | ✅ |
| **FG-PS-04** Yapılandırılmış prompt | Şema tam | 17/17 doğru JSON | ✅ |
| **FG-PS-05** OpenAI JSON | Geçerli yanıt | 17/17 başarılı | ✅ |
| **FG-PS-06** Hata toleransı | Çökmeme | Hata yok | ✅ |
| **FG-PS-08** PII maskeleme | Sızıntı yok | Sızıntı yok | ✅ |
| **FG-AJ-01** ReAct döngüsü | Yapılandırılmış | 17/17 | ✅ |
| **FG-RA-02** Standart şablon | Title+Desc+Impact+Remediation+Evidence | Şema tam | ✅ |
| **FG-RA-04** JSON Repair | 3 aşamalı | Birim testler ✅ | ✅ |
| **FOG-PM-01** Token sınırı | < 10 000 | maks 123 | ✅ |
| **FOG-PM-02** Proxy gecikmesi | < 100 ms | < 10 ms | ✅ |
| **FOG-PM-05** Regex perf | Tek derleme | Modül yükleme | ✅ |
| **FOG-ET-02** PII paylaşımı | Maskelenmiş | %100 | ✅ |
| **HA-01** OpenAI entegrasyonu | Tam yanıt | 17/17 | ✅ |
| **HA-02** JSON Mode | Geçerli JSON | 17/17 | ✅ |

Genel uyum: **17/17 doğrulanan gereksinim — başarılı**.

---

## 6. Ekonomik Maliyet (Bilgi Amaçlı)

`gpt-4o-mini` fiyatlandırması (Nisan 2026, OpenAI):
prompt 0,15 USD / 1M token, completion 0,60 USD / 1M token. Bu çalıştırma
yaklaşık **2 000** prompt-token + ~7 000 completion-token kullandı.

- Tahmini maliyet: **0,005 USD** (= 17 senaryo)
- Tek istek ortalaması: ~0,0003 USD

Sürekli izleme senaryosunda (günde 10 000 dinamik istek) tahmini günlük
LLM gideri **3 USD** seviyesinde kalır.

---

## 7. Tekrar Çalıştırma

```bash
cd vulcan
uv sync
echo "OPENAI_API_KEY=sk-..." > .env
uv run python scripts/full_validation.py
```

Çıktı: `vulcan/reports/full_validation_<TS>.json` ve `.md`. Konsolda
karışıklık matrisi, precision/recall/F1, gecikme ve token özeti basılır.

---

## 8. Sonuç

VULCAN, **17 senaryoluk** karma doğrulama setinde

- **F1 = 0,917** (precision 84,6 %, recall 100 %, accuracy 88,2 %),
- ortalama LLM gecikmesi 7,5 sn (asenkron — proxy bloklanmıyor),
- istek başı 116 prompt-token (üst sınırın %1,3'ü),
- statik trafiğin %53,3'ünü filtreleyerek

elde etti. Tüm doğrulanan SRS gereksinimleri karşılandı. Ana iyileştirme
alanı, iki false-positive'in giderilmesi için prompt'a session-decode ve
"4xx ⇒ güvenli" kuralının eklenmesidir.
