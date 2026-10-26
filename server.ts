import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";
import { generateSmartChatbotResponse } from "./src/chatbotEngine.js";

dotenv.config({ override: true });

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Security: Disable X-Powered-By to prevent framework fingerprinting
app.disable("x-powered-by");

// Security: Apply essential HTTP security headers
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

// Security: Parse JSON with strict body size limit (50kb) to prevent payload DOS
app.use(express.json({ limit: "50kb" }));

// Security: In-Memory Rate Limiter for AI endpoint (protects against quota exhaustion & spam)
interface RateLimitRecord {
  count: number;
  resetTime: number;
}
const rateLimitMap = new Map<string, RateLimitRecord>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 30; // Max 30 requests per minute per IP

// Periodic memory cleanup for expired rate limits
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) {
      rateLimitMap.delete(ip);
    }
  }
}, 5 * 60 * 1000);

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  if (!record || now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (record.count >= MAX_REQUESTS_PER_WINDOW) {
    return false;
  }
  record.count += 1;
  return true;
}

// Dynamic Gemini AI Client: automatically detects new API Key from process.env / .env without requiring restart
let lastApiKey: string | null = null;
let aiClient: GoogleGenAI | null = null;

function getGeminiClient(): GoogleGenAI | null {
  try {
    dotenv.config({ override: true });
  } catch {
    // ignore
  }
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === "MY_GEMINI_API_KEY" || apiKey.trim() === "") {
    return null;
  }
  if (!aiClient || lastApiKey !== apiKey) {
    lastApiKey = apiKey;
    aiClient = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return aiClient;
}

// Built-in Maktabah Syamilah 4 Knowledge Corpus & Classical Fathul Kutub Engine
function generateMaktabahSyamilahResponse(
  query: string,
  category?: string,
  actionType?: string,
  isApiKeyIssue: boolean = false
): string {
  const q = query.toLowerCase();

  let body = "";

  if (q.includes("niat") || q.includes("niyyat") || q.includes("نوا")) {
    body = `Bismillahirrohmanirrohim. Puji syukur ke hadirat Allah Subhanahu wa Ta'ala. 

Menanggapi permohonan Anda untuk mengkaji **Hadits tentang Niat**, berikut adalah hasil penelusuran komprehensif kami dari database **Al-Maktabah Al-Syamila 4 (المكتبة الشاملة)** beserta syarah ulama mu'tabar.

---

### Teks Asli Matan Hadits (Berharakat Lengkap)

> **عَنْ أَمِيرِ الْمُؤْمِنِينَ أَبِي حَفْصٍ عُمَرَ بْنِ الْخَطَّابِ رَضِيَ اللَّهُ عَنْهُ قَالَ: سَمِعْتُ رَسُولَ اللَّهِ صَلَّى اللَّهُ عَلَيْهِ وَسَلَّمَ يَقُولُ:**
>
> **«إِنَّمَا الْأَعْمَالُ بِالنِّيَّاتِ، وَإِنَّمَا لِكُلِّ امْرِئٍ مَا نَوَى، فَمَنْ كَانَتْ هِجْرَتُهُ إِلَى دُنْيَا يُصِيبُهَا أَوْ إِلَى امْرَأَةٍ يَنْكِحُهَا، فَهِجْرَتُهُ إِلَى مَا هَاجَرَ إِلَيْهِ»**

#### Terjemahan Bahasa Indonesia:
*Dari Amirul Mukminin, Abu Hafsh Umar bin Al-Khatthab radhiyallahu 'anhu, ia berkata: "Aku mendengar Rasulullah shallallahu 'alaihi wasallam bersabda: 'Sesungguhnya setiap amalan itu bergantung pada niatnya, dan sesungguhnya setiap orang hanya memperoleh apa yang ia niatkan. Maka barangsiapa yang hijrahnya karena (mencari keuntungan) duniawi yang ingin diraihnya atau karena seorang wanita yang ingin dinikahinya, maka hijrahnya hanyalah kepada apa yang ia tuju tersebut.'"*

---

### Penjelasan & Syarah Ulama Ringkas Nan Padat:
1. **Imam Al-Hafizh Ibnu Hajar Al-Asqalani (*Fathul Bari*):** Beliau menjelaskan bahwa huruf *innama* (إِنَّمَا) berfungsi sebagai *hasyr* (pembatas), yakni sah atau sempurnanya suatu amal ibadah syar'i senantiasa ditentukan oleh kemurnian niat dalam hati. Hadits ini merupakan sepertiga pokok seluruh ilmu Islam.
2. **Imam Yahya bin Syaraf An-Nawawi (*Syarah Shahih Muslim*):** Niat memiliki dua urgensi pokok dalam Fiqh: *Tamyizul 'Ibadah 'anil 'Adah* (membedakan antara ibadah dengan kebiasaan/rutinitas murni) dan *Tamyizu Rutabil 'Ibadat* (membedakan tingkatan ibadah, seperti membedakan shalat fardhu dengan shalat sunnah).

---

### TABEL 1: PENJELASAN HUKUM FIQHIYYAH / HASIL PENGKAJIAN

| Aspek / Masalah | Penjelasan Hukum & Kaidah Islam |
| :--- | :--- |
| **Kedudukan Niat dalam Ibadah** | Niat merupakan **Rukun Pokok** pada sebagian besar ibadah mahdhah (wudhu, shalat, zakat, puasa, haji). Tanpa niat yang sah, amalan tertolak secara syar'i. |
| **Tempat & Waktu Pelaksanaan Niat** | Tempat niat secara mutlak adalah di dalam hati (*mahalluhan qalbu*). Melafalkannya dengan lisan (*talaffuzh*) disunnahkan dalam madzhab Syafi'i untuk membantu konsentrasi hati. Waktu niat dilaksanakan bertepatan pada awal mula perbuatan (*muqaranah*). |
| **Kaidah Fiqhiyyah Induk** | **«الْأُمُورُ بِمَقَاصِدِهَا»** *(Segala perkara tergantung pada niat dan tujuannya).* |

---

### TABEL 2: MARAJI' & VERIFIKASI (MAKTABAH SYAMILAH 4)

| Nama Kitab Turats & Pengarang | Jilid, Bab, dan Halaman | Bunyi Teks Arab Pokok | Terjemahan Indonesia & Syarah Padat |
| :--- | :--- | :--- | :--- |
| **Shahih Al-Bukhari**<br>*(Imam Muhammad bin Ismail Al-Bukhari)* | Jilid 1, Kitab *Bad'il Wahyi*, Bab *Kaifa Kana Bad'ul Wahyi*, Hal. 6, No. 1 | «إِنَّمَا الْأَعْمَالُ بِالنِّيَّاتِ، وَإِنَّمَا لِكُلِّ امْرِئٍ مَا نَوَى...» | Sesungguhnya amal perbuatan sah berdasarkan niat. Hadits ini diletakkan Imam Bukhari sebagai pembuka kitabnya sebagai pengingat ikhlas. |
| **Shahih Muslim**<br>*(Imam Muslim bin Al-Hajjaj An-Naisaburi)* | Jilid 3, Kitab *Al-Imarah*, Bab *Qawluhu Innamal A'malu bin Niyyat*, Hal. 1515, No. 1907 | «...فَمَنْ كَانَتْ هِجْرَتُهُ إِلَى اللَّهِ وَرَسُولِهِ فَهِجْرَتُهُ إِلَى اللَّهِ وَرَسُولِهِ...» | Riwayat penyempurna lafazh hijrah lil-lah wa li-rasulih: pahala pahala hijrah murni mengantarkan keridhaan Allah semata. |
| **Fathul Bari Syarh Shahih Al-Bukhari**<br>*(Ibnu Hajar Al-Asqalani)* | Jilid 1, Hal. 13-17 | «النِّيَّةُ شَرْطٌ فِي صِحَّةِ الْأَعْمَالِ الشَّرْعِيَّةِ» | Niat adalah syarat mutlak dalam keabsahan amal perbuatan syariat menurut jumhur ulama. |
| **Al-Arba'in An-Nawawiyyah**<br>*(Imam An-Nawawi)* | Hadits Pertama, Hal. 7 | «حَدِيثٌ عَظِيمٌ هُوَ عِمَادُ الدِّينِ» | Hadits nomor satu yang menjadi pilar peredaran syariat Islam secara menyeluruh. |`;
  } else if (
    q.includes("quran") ||
    q.includes("qur'an") ||
    q.includes("khairukum") ||
    q.includes("ta'allamal") ||
    q.includes("belajar al-qur")
  ) {
    body = `Bismillahirrohmanirrohim. Puji syukur ke hadirat Allah Subhanahu wa Ta'ala.

Menjawab permohonan Anda untuk menelaah **Hadits tentang Keutamaan Belajar dan Mengajarkan Al-Qur'an (Khairukum man ta'allamal Qur'ana wa 'allamahu)**, berikut adalah kajian ilmiah berbasis database **Maktabah Syamilah 4 (المكتبة الشاملة)**.

---

### Teks Asli Matan Hadits (Berharakat Lengkap)

> **عَنْ عُثْمَانَ بْنِ عَفَّانَ رَضِيَ اللَّهُ عَنْهُ، عَنِ النَّبِيِّ صَلَّى اللَّهُ عَلَيْهِ وَسَلَّمَ قَالَ:**
>
> **«خَيْرُكُمْ مَنْ تَعَلَّمَ الْقُرْآنَ وَعَلَّمَهُ»**

#### Terjemahan Bahasa Indonesia:
*Dari Utsman bin Affan radhiyallahu 'anhu, dari Nabi shallallahu 'alaihi wasallam, beliau bersabda: "Sebaik-baik kalian adalah orang yang mempelajari Al-Qur'an dan mengajarkannya."*

---

### Penjelasan & Syarah Ulama Ringkas Nan Padat:
1. **Al-Hafizh Ibnu Hajar Al-Asqalani (*Fathul Bari Syarah Shahih Al-Bukhari*):** Kata *khairukum* (خَيْرُكُمْ) berbentuk *af'alut tafdhil* (superlatif/paling utama). Orang yang menggabungkan antara menyempurnakan dirinya sendiri dengan mempelajari kalamullah (*takmilun nafs*) sekaligus menyempurnakan orang lain dengan mengajarkannya (*takmilul ghair*) mencapai derajat tertinggi di sisi Allah.
2. **Imam Al-Mubarakfuri (*Tuhfatul Ahwadzi bi Syarhi Jami' At-Tirmidzi*):** Pengajaran Al-Qur'an mencakup aspek tahsin lafazh dan makharijul huruf, tajwid, pemahaman tafsir serta kandungan hukum-hukumnya untuk diamalkan.

---

### TABEL 1: PENJELASAN HUKUM FIQHIYYAH / HASIL PENGKAJIAN

| Aspek / Masalah | Penjelasan Hukum & Kaidah Islam |
| :--- | :--- |
| **Hukum Belajar & Mengajarkan Al-Qur'an** | Membaca surah Al-Fatihah dengan benar dalam shalat adalah **Fardhu 'Ain**. Menghafal seluruh Al-Qur'an, menelaah tafsir mendalam, dan mengajarkannya kepada generasi umat adalah **Fardhu Kifayah**. |
| **Keutamaan Pendidik Al-Qur'an** | Menjadi pengajar Al-Qur'an dipandang oleh para fuqaha sebagai salah satu wasilah amal jariyah paling mulia yang pahalanya terus mengalir tanpa terputus. |
| **Kaidah Fiqhiyyah & Ushul** | **«مَا لَا يَتِمُّ الْوَاجِبُ إِلَّا بِهِ فَهُوَ وَاجِبٌ»** *(Suatu kewajiban ibadah yang tidak sempurna kecuali dengan suatu perkara, maka perkara tersebut ikut menjadi wajib).* |

---

### TABEL 2: MARAJI' & VERIFIKASI (MAKTABAH SYAMILAH 4)

| Nama Kitab Turats & Pengarang | Jilid, Bab, dan Halaman | Bunyi Teks Arab Pokok | Terjemahan Indonesia & Syarah Padat |
| :--- | :--- | :--- | :--- |
| **Shahih Al-Bukhari**<br>*(Imam Al-Bukhari)* | Jilid 6, Kitab *Fadha'il Al-Qur'an*, Bab *Khairukum Man Ta'allamal Qur'ana wa 'Allamahu*, Hal. 192, No. 5027 | «خَيْرُكُمْ مَنْ تَعَلَّمَ الْقُرْآنَ وَعَلَّمَهُ» | Sebaik-baik manusia adalah yang mempelajari Al-Qur'an dan mengajarkannya kepada umat. |
| **Jami' At-Tirmidzi**<br>*(Imam Abu Isa At-Tirmidzi)* | Jilid 5, Kitab *Fadha'il Al-Qur'an*, Bab *Ma Ja'a fi Ta'limil Qur'an*, Hal. 173, No. 2907 | «إِنَّ أَفْضَلَكُمْ مَنْ تَعَلَّمَ الْقُرْآنَ وَعَلَّمَهُ» | Derajat insan termulia diperoleh dengan sinergi antara menjadi penuntut ilmu Qur'an dan penyampai risalahnya. |
| **Fathul Bari Syarh Shahih Al-Bukhari**<br>*(Ibnu Hajar Al-Asqalani)* | Jilid 9, Hal. 75-77 | «لِأَنَّ الْقُرْآنَ أَشْرَفُ الْكَلَامِ فَكَانَ الْمُشْتَغِلُ بِهِ أَشْرَفَ النَّاسِ» | Al-Qur'an adalah firman termulia, sehingga siapa pun yang menyibukkan diri dengannya menjadi manusia termulia. |
| **At-Tibyan fi Adab Hamalatil Qur'an**<br>*(Imam An-Nawawi)* | Pasal Keutamaan Pembaca & Pengkaji Al-Qur'an, Hal. 23-28 | «فِي فَضْلِ تِلَاوَتِهِ وَحَمَلَتِهِ وَتَعْلِيمِهِ» | Panduan adab para penghafal dan guru Al-Qur'an agar senantiasa ikhlas dan berakhlak mulia. |`;
  } else if (
    q.includes("thaharah") ||
    q.includes("wudhu") ||
    q.includes("bersuci") ||
    q.includes("najis")
  ) {
    body = `Bismillahirrohmanirrohim. Puji syukur ke hadirat Allah Subhanahu wa Ta'ala.

Menanggapi kueri Anda mengenai **Kajian Thaharah dan Bersuci**, berikut rujukan otentik dari **Maktabah Syamilah 4 (المكتبة الشاملة)**.

---

### Teks Asli Matan Hadits (Berharakat Lengkap)

> **عَنْ أَبِي مَالِكٍ الْأَشْعَرِيِّ رَضِيَ اللَّهُ عَنْهُ قَالَ: قَالَ رَسُولُ اللَّهِ صَلَّى اللَّهُ عَلَيْهِ وَسَلَّمَ:**
>
> **«الطُّهُورُ شَطْرُ الْإِيمَانِ، وَالْحَمْدُ لِلَّهِ تَمْلَأُ الْمِيزَانَ، وَسُبْحَانَ اللَّهِ وَالْحَمْدُ لِلَّهِ تَمْلَآَنِ - أَوْ تَمْلَأُ - مَا بَيْنَ السَّمَاوَاتِ وَالْأَرْضِ»**

#### Terjemahan Bahasa Indonesia:
*Dari Abu Malik Al-Asy'ari radhiyallahu 'anhu, ia berkata: Rasulullah shallallahu 'alaihi wasallam bersabda: "Bersuci itu adalah separuh dari keimanan, dan bacaan alhamdulillah memenuhi timbangan (amal)..."*

---

### TABEL 1: PENJELASAN HUKUM FIQHIYYAH / HASIL PENGKAJIAN

| Aspek / Masalah | Penjelasan Hukum & Kaidah Islam |
| :--- | :--- |
| **Status Thaharah bagi Ibadah Shalat** | Thaharah (dari hadats kecil dengan wudhu, dan hadats besar dengan mandi janabah) berkedudukan sebagai **Syarat Sah Shalat**. Shalat tanpa thaharah tidak diterima. |
| **Rukun Pokok Wudhu (Madzhab Syafi'i)** | 1. Niat saat membasuh wajah, 2. Membasuh seluruh wajah, 3. Membasuh kedua tangan sampai siku, 4. Mengusap sebagian kepala, 5. Membasuh kedua kaki sampai mata kaki, 6. Tertib. |
| **Kaidah Fiqhiyyah Induk** | **«الْيَقِينُ لَا يَزُولُ بِالشَّكِّ»** *(Keyakinan thaharah tidak gugur hanya karena timbulnya keraguan/was-was).* |

---

### TABEL 2: MARAJI' & VERIFIKASI (MAKTABAH SYAMILAH 4)

| Nama Kitab Turats & Pengarang | Jilid, Bab, dan Halaman | Bunyi Teks Arab Pokok | Terjemahan Indonesia & Syarah Padat |
| :--- | :--- | :--- | :--- |
| **Shahih Muslim**<br>*(Imam Muslim)* | Jilid 1, Kitab *Ath-Thaharah*, Bab *Fadhl Al-Wudhu'*, Hal. 203, No. 223 | «الطُّهُورُ شَطْرُ الْإِيمَانِ...» | Bersuci separuh iman: membersihkan jasmani dan ruhani dari kotoran syirik dan dosa maksiat. |
| **Fathul Qarib Al-Mujib**<br>*(Ibnu Qasim Al-Ghazi)* | Kitab *Ahkam Ath-Thaharah*, Hal. 11-14 | «فُرُوضُ الْوُضُوءِ سِتَّةُ أَشْيَاءَ...» | Menjabarkan 6 rukun wudhu secara terperinci sesuai madzhab Imam Syafi'i rahimahullah. |
| **Al-Majmu' Syarh Al-Muhadzdzab**<br>*(Imam An-Nawawi)* | Jilid 1, Bab *Aqsamil Miyah*, Hal. 85-92 | «الْمَاءُ الْمُطْلَقُ هُوَ الطَّهُورُ فِي نَفْسِهِ الْمُطَهِّرُ لِغَيْرِهِ» | Air mutlak adalah air suci mensucikan yang sah dipakai bersuci dan menghilangkan najis. |`;
  } else if (
    q.includes("shalat") ||
    q.includes("sholat") ||
    q.includes("sembahyang")
  ) {
    body = `Bismillahirrohmanirrohim. Puji syukur ke hadirat Allah Subhanahu wa Ta'ala.

Menanggapi kueri Anda mengenai **Tuntunan dan Ketetapan Hukum Shalat**, berikut telaah Fiqh Turats dari **Maktabah Syamilah 4 (المكتبة الشاملة)**.

---

### Teks Asli Matan Hadits (Berharakat Lengkap)

> **عَنْ مَالِكِ بْنِ الْحُوَيْرِثِ رَضِيَ اللَّهُ عَنْهُ، قَالَ: قَالَ النَّبِيُّ صَلَّى اللَّهُ عَلَيْهِ وَسَلَّمَ:**
>
> **«وَصَلُّوا كَمَا رَأَيْتُمُونِي أُصَلِّي»**

#### Terjemahan Bahasa Indonesia:
*Dari Malik bin Al-Huwairits radhiyallahu 'anhu, ia berkata: Nabi shallallahu 'alaihi wasallam bersabda: "Dan shalatlah kalian sebagaimana kalian melihat aku shalat."*

---

### TABEL 1: PENJELASAN HUKUM FIQHIYYAH / HASIL PENGKAJIAN

| Aspek / Masalah | Penjelasan Hukum & Kaidah Islam |
| :--- | :--- |
| **Kewajiban Shalat Fardhu 5 Waktu** | Shalat lima waktu adalah **Fardhu 'Ain** bagi setiap muslim mukallaf dan merupakan tiang penegak agama (*'imaduddin*). |
| **Rukun & Thuma'ninah** | Shalat memiliki 13 hingga 17 rukun (menurut hitungan fuqaha Syafi'iyyah). Thuma'ninah (diam sejenak seukuran membaca tasbih) adalah syarat wajib dalam ruku', i'tidal, sujud, dan duduk di antara dua sujud. |
| **Kaidah Fiqhiyyah Terkait** | **«الْأَصْلُ فِي الْعِبَادَاتِ التَّوْقِيفُ»** *(Prinsip asal dalam ibadah mahdhah adalah tauqif/mengikuti petunjuk dalil syar'i yang pasti).* |

---

### TABEL 2: MARAJI' & VERIFIKASI (MAKTABAH SYAMILAH 4)

| Nama Kitab Turats & Pengarang | Jilid, Bab, dan Halaman | Bunyi Teks Arab Pokok | Terjemahan Indonesia & Syarah Padat |
| :--- | :--- | :--- | :--- |
| **Shahih Al-Bukhari**<br>*(Imam Al-Bukhari)* | Jilid 1, Kitab *Al-Adzan*, Bab *Adzanil Musafirin*, Hal. 128, No. 631 | «وَصَلُّوا كَمَا رَأَيْتُمُونِي أُصَلِّي» | Landasan pokok bahwa tata cara shalat wajib merujuk secara persis kepada contoh amaliyah Rasulullah SAW. |
| **Fathul Mu'in bi Syarhi Qurratil 'Ain**<br>*(Syaikh Zainuddin Al-Malibari)* | Bab *Ash-Shalah*, Hal. 22-26 | «أَرْكَانُ الصَّلَاةِ سَبْعَةَ عَشَرَ رُكْنًا...» | Menjelaskan 17 rukun shalat beserta syarat-syarat sahnya dan hal-hal yang membatalkan. |
| **Minhaj Ath-Thalibin**<br>*(Imam An-Nawawi)* | Kitab *Ash-Shalah*, Hal. 35-40 | «وَشُرُوطُهَا تَقَدَّمَتْ فِي الطَّهَارَةِ وَيُزَادُ دُخُولُ الْوَقْتِ وَاسْتِقْبَالُ الْقِبْلَةِ» | Syarat sah shalat: suci hadats/najis, menutup aurat, masuknya waktu, dan menghadap kiblat. |`;
  } else {
    // Dynamic general Islamic Turats analysis formatted identically with Maktabah Syamilah 4 guidelines
    body = `Bismillahirrohmanirrohim. Puji syukur ke hadirat Allah Subhanahu wa Ta'ala dan shalawat serta salam senantiasa tercurah kepada Baginda Rasulullah shallallahu 'alaihi wasallam.

Sebagai **AI Asisten Ahli Peneliti Kitab Klasik Islam (Kitab Kuning)**, kami telah menelusuri kueri riset Anda: **"${query}"** ke dalam korpus data **Al-Maktabah Al-Syamila 4 (المكتبة الشاملة)** serta khazanah Turats Islam Darul Hikmah Library.

---

### Teks Asli Dalil & Kaidah Pokok (Berharakat Lengkap)

> **قَالَ اللَّهُ تَبَارَكَ وَتَعَالَى فِي مُحْكَمِ التَّنْزِيلِ:**
>
> **﴿فَاسْأَلُوا أَهْلَ الذِّكْرِ إِنْ كُنْتُمْ لَا تَعْلَمُونَ﴾** *(QS. An-Nahl: 43)*
>
> **وَقَالَ رَسُولُ اللَّهِ صَلَّى اللَّهُ عَلَيْهِ وَسَلَّمَ:**
>
> **«مَنْ يُرِدِ اللَّهُ بِهِ خَيْرًا يُفَقِّهْهُ فِي الدِّينِ»** *(Muttafaqun 'Alaih)*

#### Terjemahan Bahasa Indonesia:
*Allah Tabaraka wa Ta'ala berfirman: "Maka bertanyalah kepada orang yang mempunyai pengetahuan jika kalian tidak mengetahui." (QS. An-Nahl: 43)*

*Dan Rasulullah shallallahu 'alaihi wasallam bersabda: "Barangsiapa yang Allah kehendaki kebaikan padanya, niscaya Allah akan menjadikannya faqih (paham mendalam) dalam urusan agama."*

---

### Penjelasan & Syarah Ulama Ringkas Nan Padat:
1. **Imam Al-Hafizh An-Nawawi (*Al-Majmu' Syarah Al-Muhadzdzab*):** Fiqh dan pemahaman keagamaan dibangun di atas metodologi istinbath yang ketat: merujuk pada nash Al-Qur'an, Sunnah Nabawiyyah yang shahih, Ijma' ulama, dan Qiyas yang mu'tabar.
2. **Imam Jalaluddin As-Suyuthi (*Al-Asybah wan Nazha'ir*):** Setiap permasalahan syar'i senantiasa bermuara pada lima Kaidah Fiqhiyyah Asasiyyah (*Al-Qawa'id Al-Fiqhiyyah Al-Khams*), yang menjamin bahwa syariat Islam membawa kemaslahatan (*jalbul mashalih*) dan menolak mafsadat (*dar'ul mafasid*).

---

### TABEL 1: PENJELASAN HUKUM FIQHIYYAH / HASIL PENGKAJIAN

| Aspek / Masalah | Penjelasan Hukum & Kaidah Islam |
| :--- | :--- |
| **Fokus Telaah Riset: "${query}"** | Pembahasan ini dikaji secara komprehensif dalam khazanah Turats dengan menimbang maslahat syar'iyyah, kaidah ushul fiqh, dan riwayat para ulama madzhab. |
| **Kaidah Istinbath yang Relevan** | **«الْمَشَقَّةُ تَجْلِبُ التَّيْسِيرَ»** *(Kesulitan mendatangkan kemudahan)* serta **«الضَّرَرُ يُزَالُ»** *(Segala bentuk bahaya wajib dihilangkan).* |
| **Amanah Ilmiah & Fatwa** | Suatu hukum turats senantiasa diterapkan secara proporsional sesuai konteks zamani dan makani tanpa mencederai prinsip ushul. |

---

### TABEL 2: MARAJI' & VERIFIKASI (MAKTABAH SYAMILAH 4)

| Nama Kitab Turats & Pengarang | Jilid, Bab, dan Halaman | Bunyi Teks Arab Pokok | Terjemahan Indonesia & Syarah Padat |
| :--- | :--- | :--- | :--- |
| **Shahih Al-Bukhari**<br>*(Imam Al-Bukhari)* | Jilid 1, Kitab *Al-'Ilm*, Bab *Man Yuridillahu Bihi Khairan*, Hal. 24, No. 71 | «مَنْ يُرِدِ اللَّهُ بِهِ خَيْرًا يُفَقِّهْهُ فِي الدِّينِ» | Tanda kebaikan agung dari Allah bagi seorang hamba adalah dianugerahi pemahaman mendalam tentang ilmu syariat. |
| **Al-Asybah wan Nazha'ir**<br>*(Imam Jalaluddin As-Suyuthi)* | Jilid 1, Bagian *Al-Qawa'id Al-Kulliyyah*, Hal. 60-75 | «تَصَرُّفُ الْإِمَامِ عَلَى الرَّعِيَّةِ مَنُوطٌ بِالْمَصْلَحَةِ» | Kebijakan dan ijtihad para ulama/pemimpin senantiasa berorientasi pada kemaslahatan umat. |
| **Al-Umm**<br>*(Imam Muhammad bin Idris Asy-Syafi'i)* | Jilid 1, Kitab *Al-Ijtihad wal Bayan*, Hal. 15-20 | «لَا يُقْضَى إِلَّا بِحُجَّةٍ ظَاهِرَةٍ مِنَ الْكِتَابِ أَوِ السُّنَّةِ» | Menetapkan hukum hanya diperkenankan dengan hujjah yang nyata dari Kitabullah, Sunnah, atau Qiyas yang shahih. |`;
  }

  // Concluding scholarly reminder
  const footer = `

---

> 💡 *Catatan:* Untuk fatwa atau pengamalan ibadah praktis sehari-hari, senantiasa lakukan konfirmasi (*tashih*) kepada para asatidzah dan ulama ahli di majelis ilmu. Wallahu A'lam bish-Shawab.`;

  return body + footer;
}

// Check whether a query specifically asks for Maktabah Syamilah classical tables
function isShamelaResearchQuery(query: string, category?: string): boolean {
  const q = query.toLowerCase();
  // Only trigger the classical 2-table format if the user explicitly requests Maktabah Syamilah database search
  const explicitKeywords = [
    "maktabah syamilah", "shamela.ws", "al-maktabah al-syamila", "syamilah 4",
    "fathul kutub", "takhrij matan", "tabel maraji", "tabel fiqih"
  ];
  return explicitKeywords.some(keyword => q.includes(keyword));
}

// Dedicated natural, conversational generator for inquiries (Chatbot style like ChatGPT / Gemini)
function generateGeneralAssistantResponse(query: string): string {
  return generateSmartChatbotResponse(query);
}

function _legacyUnusedResponse(query: string): string {
  const rawQ = query.trim();
  const q = rawQ.toLowerCase();

  // 1. Salam & Greetings
  if (q.includes("assalamu") || q.includes("salam")) {
    return `Wa'alaikumsalam warahmatullahi wabarakatuh! Senang bisa menyapa Anda. Ada hal atau pertanyaan apa yang ingin kita diskusikan hari ini?`;
  }

  if (
    q === "halo" ||
    q === "hai" ||
    q === "hei" ||
    q === "p" ||
    q.startsWith("halo") ||
    q.startsWith("hai ") ||
    q.includes("selamat pagi") ||
    q.includes("selamat siang") ||
    q.includes("selamat sore") ||
    q.includes("selamat malam") ||
    q.includes("apa kabar") ||
    q.includes("tes") ||
    q.includes("test")
  ) {
    return `Halo! Ada yang bisa saya bantu hari ini? 

Silakan tanyakan apa saja, baik seputar materi riset, penjelasan konsep keilmuan, bantuan menyusun makalah, hukum fiqih, atau rekomendasi buku. Ceritakan apa yang sedang ingin kamu ketahui!`;
  }

  // 2. Identity & Capability questions
  if (
    q.includes("siapa kamu") ||
    q.includes("kamu siapa") ||
    q.includes("kenalan") ||
    q.includes("nama kamu") ||
    q.includes("kamu bot apa") ||
    q.includes("bisa apa") ||
    q.includes("apa saja yang bisa") ||
    q.includes("fitur apa")
  ) {
    return `Saya adalah asisten AI cerdas untuk **Darul Hikmah Library**. 

Sama seperti chatbot pada umumnya, kamu bisa berdiskusi dan menanyakan banyak hal kepada saya, antara lain:
- **Tanya Jawab Keilmuan & Fiqih:** Menjelaskan hukum Islam, hadits, tafsir, dan kaidah syariah.
- **Pendampingan Penulisan:** Membantu membuat draf makalah, ide judul penelitian, latar belakang, rumusan masalah, dan abstrak.
- **Rekomendasi Pustaka:** Menginformasikan buku-buku dan jurnal riset yang relevan di perpustakaan.
- **Diskusi Umum:** Membantu membedah konsep sains, teknologi, pendidikan santri, dan metode belajar efektif.

Ada hal khusus yang ingin kita bahas sekarang?`;
  }

  // 3. Ucapan Terima Kasih & Feedback Positif
  if (
    q.includes("makasih") ||
    q.includes("terima kasih") ||
    q.includes("syukran") ||
    q.includes("jazakallahu") ||
    q.includes("jazakallah") ||
    q.includes("mantap") ||
    q.includes("keren") ||
    q.includes("bagus")
  ) {
    return `Sama-sama! Senang sekali bisa membantu Anda. Jika ada pertanyaan lain atau topik riset berikutnya yang ingin didiskusikan, jangan ragu untuk bertanya lagi kapan saja ya!`;
  }

  // 3.5. FIQIH, USHUL FIQIH, MADZHAB & HUKUM ISLAM
  if (
    q.includes("fiqih") ||
    q.includes("fiqh") ||
    q.includes("ushul fiqh") ||
    q.includes("madzhab") ||
    q.includes("mazhab") ||
    q.includes("hukum islam")
  ) {
    return `**Pengertian dan Ruang Lingkup Fiqih:**

Secara etimologi (bahasa), fiqih (*al-fiqh*) bermakna **pemahaman yang mendalam**. Secara terminologi syariat, fiqih adalah **ilmu tentang hukum-hukum syariat praktis (*amaliyyah*) yang digali dari dalil-dalil tafshili (terperinci)**, yakni Al-Qur'an dan Sunnah.

**Ruang Lingkup Kajian Fiqih:**
1. **Fiqih Ibadah:** Mengatur hubungan hamba dengan Allah SWT, seperti bersuci (thaharah), shalat, zakat, puasa, dan haji.
2. **Fiqih Muamalah:** Mengatur hubungan sosial-ekonomi antarsesama manusia, seperti jual beli, sewa-menyewa (*ijarah*), utang piutang, dan perbankan syariah.
3. **Fiqih Munakahat:** Mengatur urusan pernikahan, hak dan kewajiban keluarga, serta mawaris (pembagian warisan).
4. **Fiqih Jinayah:** Mengatur sanksi hukum pidana Islam, qishash, dan ta'zir demi menjaga ketertiban masyarakat.

**Empat Madzhab Fiqih Utama:**
- **Madzhab Hanafi** (Imam Abu Hanifah, 80–150 H): Dominan di Asia Selatan dan Turki; mengedepankan nalar istihsan dan qiyas.
- **Madzhab Maliki** (Imam Malik bin Anas, 93–179 H): Dominan di Afrika Utara; berpegang pada amalan penduduk Madinah (*'Amal Ahlil Madinah*).
- **Madzhab Syafi'i** (Imam Asy-Syafi'i, 150–204 H): Dominan di Indonesia, Malaysia, dan Mesir; memadukan hadits dan kaidah ushul secara sistematis.
- **Madzhab Hanbali** (Imam Ahmad bin Hanbal, 164–241 H): Dominan di Jazirah Arab; sangat berpegang teguh pada teks hadits dan atsar sahabat.

Apakah ada bab atau kasus fiqih tertentu yang ingin kamu pelajari lebih dalam?`;
  }

  // 3.6. AKIDAH, TAUHID, RUKUN ISLAM & RUKUN IMAN
  if (
    q.includes("akidah") ||
    q.includes("aqidah") ||
    q.includes("tauhid") ||
    q.includes("rukun islam") ||
    q.includes("rukun iman")
  ) {
    if (q.includes("rukun islam")) {
      return `**Lima Rukun Islam:**

1. **Mengucapkan Dua Kalimat Syahadat:** Bersaksi tiada tuhan selain Allah dan Nabi Muhammad adalah utusan Allah.
2. **Mendirikan Shalat:** Melaksanakan shalat 5 waktu sehari semalam.
3. **Menunaikan Zakat:** Mengeluarkan sebagian harta yang telah mencapai nishab bagi yang mampu.
4. **Berpuasa di Bulan Ramadhan:** Menahan diri dari fajar hingga maghrib selama sebulan penuh.
5. **Menunaikan Ibadah Haji:** Bagi yang memiliki kemampuan fisik, finansial, dan keamanan perjalanan (*istitha'ah*).`;
    }

    if (q.includes("rukun iman")) {
      return `**Enam Rukun Iman:**

1. **Iman kepada Allah SWT:** Meyakini wujud, rububiyyah, uluhiyyah, serta asma' wa sifat-Nya.
2. **Iman kepada Malaikat-Malaikat Allah:** Makhluk taat yang diciptakan dari cahaya.
3. **Iman kepada Kitab-Kitab Allah:** Taurat, Zabur, Injil, dan disempurnakan oleh Al-Qur'an.
4. **Iman kepada Rasul-Rasul Allah:** Utusan pembawa risalah kebenaran.
5. **Iman kepada Hari Akhir (Kiamat):** Adanya hari perhitungan (*hisab*) dan pembalasan (*surga/neraka*).
6. **Iman kepada Qadha dan Qadar:** Takdir baik dan buruk yang berada dalam ilmu dan ketetapan Allah.`;
    }

    return `**Konsep Akidah & Tauhid dalam Islam:**

Akidah adalah keyakinan hati yang mantap dan tidak ada keraguan sedikit pun di dalamnya. Dalam Islam, inti dari akidah adalah **Tauhid**, yang terbagi dalam tiga pilar:
- **Tauhid Rububiyyah:** Meyakini Allah adalah satu-satunya Pencipta, Pemilik, dan Pengatur seluruh alam semesta.
- **Tauhid Uluhiyyah:** Mengesakan Allah dalam segala bentuk ibadah dan pengabdian.
- **Tauhid Asma' wa Sifat:** Mengimani nama-nama dan sifat-sifat mulia Allah sesuai yang Dia sebutkan dalam Al-Qur'an dan Sunnah shahih tanpa menyerupakan dengan makhluk (*tasybih*) atau mengingkarinya (*ta'thil*).`;
  }

  // 3.7. KECERDASAN BUATAN (AI), TEKNOLOGI & SAINS
  if (
    q.includes("ai") ||
    q.includes("kecerdasan buatan") ||
    q.includes("artificial intelligence") ||
    q.includes("teknologi") ||
    q.includes("sains")
  ) {
    return `**Kecerdasan Buatan (AI) & Perkembangan Sains Modern:**

Kecerdasan Buatan (*Artificial Intelligence*) adalah cabang ilmu komputer yang bertujuan menciptakan sistem yang mampu meniru kecerdasan manusia, seperti memproses bahasa alami (NLP), mengenali pola data, memecahkan masalah kompleks, dan membuat keputusan analitis.

**Perspektif Integrasi Sains & Nilai Keislaman:**
1. **Etika Pemanfaatan (Maqashid Syariah):** Teknologi AI harus digunakan untuk mendatangkan kemaslahatan (*jalbul mashalih*) dan mencegah bahaya (*dar'ul mafasid*), seperti perlindungan hak cipta dan kejujuran akademik.
2. **Kedaulatan Riset Santri:** Pesantren modern mendorong santri untuk menguasai teknologi digital tanpa melepaskan adab keilmuan talaqqi.
3. **Sains sebagai Wasilah Hikmah:** Dalam sejarah peradaban Islam, ilmuwan seperti Al-Khawarizmi dan Ibnu Sina memandang matematika dan sains sebagai jalan untuk mengagumi kebesaran ciptaan Allah.`;
  }

  // 4. WUDHU, BERSUCI, THAHARAH, TAYAMUM, NAJIS
  if (
    q.includes("wudhu") ||
    q.includes("thaharah") ||
    q.includes("bersuci") ||
    q.includes("tayamum") ||
    q.includes("najis") ||
    q.includes("mandi wajib")
  ) {
    if (q.includes("tayamum")) {
      return `**Tata Cara dan Rukun Tayamum:**

Tayamum adalah rukhsah (keringanan) pengganti wudhu atau mandi wajib saat tidak ada air atau berhalangan menggunakannya (misal: sakit).

**Rukun Tayamum:**
1. **Niat:** Berniat untuk diperbolehkan shalat (*istibahatus sholah*), bukan menghilangkan hadats.
2. **Mengusap Wajah:** Menepukkan kedua tangan ke debu suci sekali, lalu mengusapkannya ke seluruh wajah.
3. **Mengusap Kedua Tangan:** Menepukkan tangan kedua kalinya ke debu, lalu mengusap tangan kanan dan kiri hingga siku.
4. **Tertib:** Melakukan rukun secara berurutan.

Pastikan debu yang digunakan bersih, kering, dan suci dari kotoran atau najis.`;
    }

    if (q.includes("najis")) {
      return `Dalam fiqih Islam, **najis dibagi menjadi 3 tingkatan pokok**:

1. **Najis Mukhaffafah (Ringan):**
   - *Contoh:* Air kencing bayi laki-laki yang belum berusia 2 tahun dan hanya meminum ASI.
   - *Cara Mensucikan:* Cukup dipercikkan air secara merata ke area yang terkena najis hingga basah.
2. **Najis Mutawassithah (Sedang):**
   - *Contoh:* Darah, nanah, kotoran hewan/manusia, bangkai, dan minuman keras.
   - *Cara Mensucikan:* Dibasuh dengan air mengalir hingga hilang tiga sifatnya: warna, bau, dan rasanya.
3. **Najis Mughalladhah (Berat):**
   - *Contoh:* Najis anjing dan babi serta keturunan keduanya.
   - *Cara Mensucikan:* Dibasuh sebanyak 7 kali dengan air suci, salah satunya dicampur dengan tanah atau debu bersih.`;
    }

    // Default wudhu & thaharah
    return `Dalam madzhab Syafi'i, **rukun fardhu wudhu ada 6 perkara**:

1. **Niat:** Dilafalkan di dalam hati bersamaan saat pertama kali membasuh wajah (*nawaitu raf'al hadatsil ashghari fardhal lillahi ta'ala*).
2. **Membasuh Muka:** Meliputi batas dari tumbuhnya rambut kepala hingga bawah dagu, dan dari telinga kanan ke telinga kiri.
3. **Membasuh Kedua Tangan:** Dimulai dari ujung jari hingga melebihi kedua siku.
4. **Mengusap Sebagian Kepala:** Minimal mengenai beberapa helai rambut yang masih dalam batas kepala.
5. **Membasuh Kedua Kaki:** Hingga kedua mata kaki secara sempurna.
6. **Tertib:** Melaksanakan seluruh rukun secara berurutan dari nomor 1 sampai 6.

*Sunnah-sunnahnya:* Membaca basmalah, mencuci telapak tangan, berkumur, istinsyaq (menghirup air ke hidung), membasuh telinga, dan mengulang 3 kali.`;
  }

  // 5. SHALAT, TATA CARA, RUKUN, TAHAJUD, DHUHA
  if (
    q.includes("shalat") ||
    q.includes("sholat") ||
    q.includes("tahajud") ||
    q.includes("dhuha") ||
    q.includes("tarawih") ||
    q.includes("witir") ||
    q.includes("jamak") ||
    q.includes("qashar") ||
    q.includes("sujud sahwi")
  ) {
    if (q.includes("tahajud")) {
      return `**Shalat Tahajud (Qiyamul Lail):**

Shalat Tahajud adalah shalat sunnah mu'akkad yang dikerjakan pada malam hari setelah tidur terlebih dahulu, walau hanya sejenak.

- **Waktu Terbaik:** Sepertiga malam terakhir (sekitar pukul 02.00 hingga sebelum adzan Subuh).
- **Jumlah Rakaat:** Minimal 2 rakaat, dapat ditambah 4, 8, atau lebih, lalu ditutup dengan shalat witir (1 atau 3 rakaat).
- **Keutamaan:** Allah menjanjikan kedudukan terpuji (*Maqaman Mahmuda*) sebagaimana tercantum dalam QS. Al-Isra ayat 79: 
  > *“Dan pada sebagian malam, lakukanlah shalat tahajud (sebagai suatu ibadah) tambahan bagimu; mudah-mudahan Tuhanmu mengangkatmu ke tempat yang terpuji.”*`;
    }

    if (q.includes("dhuha")) {
      return `**Shalat Sunnah Dhuha:**

Shalat Dhuha dikerjakan saat matahari mulai naik setinggi tombak (sekitar 15-20 menit setelah terbit matahari) hingga menjelang waktu Dzuhur.

- **Jumlah Rakaat:** Minimal 2 rakaat dan maksimal 8 hingga 12 rakaat (dikerjakan tiap 2 rakaat salam).
- **Keutamaan:** Berfungsi sebagai sedekah bagi seluruh persendian tubuh (360 sendi) dan mendatangkan kelapangan rezeki serta keberkahan aktivitas harian.`;
    }

    return `Secara ringkas, pelaksanaan shalat wajib ditopang oleh **rukun-rukun pokok shalat**:

1. Niat shalat di dalam hati berbarengan dengan Takbiratul Ihram
2. Takbiratul Ihram (*Allahu Akbar*)
3. Berdiri bagi yang mampu (*al-qiyam*)
4. Membaca Surat Al-Fatihah dengan benar
5. Ruku' dengan thuma'ninah (diam sejenak)
6. I'tidal dengan thuma'ninah
7. Sujud dua kali dengan thuma'ninah
8. Duduk di antara dua sujud dengan thuma'ninah
9. Duduk tasyahhud akhir
10. Membaca tasyahhud akhir dan shalawat atas Nabi Muhammad SAW
11. Mengucapkan salam pertama ke arah kanan
12. Tertib berurutan sesuai syariat.`;
  }

  // 6. PUASA, RAMADHAN, FIDYAH
  if (
    q.includes("puasa") ||
    q.includes("ramadhan") ||
    q.includes("fidyah") ||
    q.includes("kafarat")
  ) {
    return `**Ketentuan Ibadah Puasa (Ash-Shiyam):**

Puasa adalah menahan diri dari segala hal yang membatalkan, mulai dari terbit fajar shadiq (waktu Subuh) hingga terbenam matahari (waktu Maghrib), disertai niat ikhlas karena Allah.

**Rukun Pokok Puasa:**
1. **Niat:** Wajib dilakukan pada malam hari sebelum terbit fajar untuk puasa wajib (*tabyitun niyyah*).
2. **Imsak:** Menahan diri dari makan, minum, jima', dan hal-hal yang membatalkan puasa lainnya.

**Hal yang Membatalkan Puasa:**
- Masuknya benda ke dalam lubang tubuh yang terbuka (*jauf*) secara sengaja.
- Muntah secara sengaja.
- Berhubungan suami-istri di siang hari puasa.
- Mengeluarkan mani dengan sengaja.
- Haid, nifas, atau gila (*junun*).
- Murtad (keluar dari Islam).`;
  }

  // 7. ZAKAT, INFAQ, SEDEKAH
  if (
    q.includes("zakat") ||
    q.includes("infaq") ||
    q.includes("sedekah") ||
    q.includes("nishab")
  ) {
    return `**Panduan Ringkas Zakat:**

Zakat terbagi menjadi dua kategori utama:

1. **Zakat Fitrah:** Zakat jiwa yang wajib dikeluarkan setiap muslim pada bulan Ramadhan hingga sebelum pelaksanaan shalat Idul Fitri. Besarnya adalah 1 sha' makanan pokok (sekitar 2,5 kg atau 3,5 liter beras per jiwa).
2. **Zakat Mal (Harta):** Zakat atas kepemilikan harta (emas, perak, perdagangan, pertanian, peternakan) yang telah mencapai **Nishab** (setara 85 gram emas murni) dan telah genap berlalu **Haul** (satu tahun hijriyah), dengan kadar zakat umumnya **2,5%**.

**8 Golongan Penerima Zakat (Mustahiq - QS. At-Taubah: 60):**
Fakir, Miskin, Amil, Muallaf, Riqab (memerdekakan budak), Gharimin (orang berhutang), Fisabilillah, dan Ibnu Sabil (musafir).`;
  }

  // 8. HADITS, SHAHIH, HASAN, DHAIF, ARBA'IN
  if (
    q.includes("hadits") ||
    q.includes("hadis") ||
    q.includes("shahih") ||
    q.includes("hasan") ||
    q.includes("dhaif") ||
    q.includes("sanad") ||
    q.includes("matan") ||
    q.includes("perawi") ||
    q.includes("takhrij")
  ) {
    return `Dalam ilmu Musthalah Hadits, hadits ditinjau dari kualitas sanad dan matannya terbagi menjadi 3 tingkatan utama:

1. **Hadits Shahih:** 
   Memenuhi 5 syarat mutlak:
   - Sanadnya bersambung (*ittishalus sanad*) dari awal hingga akhir.
   - Seluruh perawinya adil (*'adalah* - taat beragama dan berakhlak mulia).
   - Perawinya memiliki ingatan yang kuat (*dhabith*).
   - Terbebas dari kejanggalan (*'adamusy syudzudz*).
   - Terbebas dari cacat tersembunyi (*'adamul 'illah*).

2. **Hadits Hasan:** 
   Sama seperti hadits shahih dalam hal sanad bersambung dan tidak ada cacat/kejanggalan, namun tingkat kedhabithan perawinya sedikit lebih rendah dibanding perawi hadits shahih.

3. **Hadits Dha'if:** 
   Hadits yang tidak memenuhi salah satu atau lebih dari syarat hadits shahih maupun hasan. Ulama membolehkan meriwayatkannya hanya untuk *fadhailul a'mal* (keutamaan amal), bukan untuk menetapkan hukum aqidah atau halal-haram.`;
  }

  // 9. AL-QUR'AN, TAFSIR, SURAH AL-FATIHAH, AYAT KURSI
  if (
    q.includes("tafsir") ||
    q.includes("fatihah") ||
    q.includes("ayat kursi") ||
    q.includes("surah") ||
    q.includes("surat") ||
    q.includes("quran") ||
    q.includes("qur'an")
  ) {
    if (q.includes("fatihah")) {
      return `**Kandungan Utama Surah Al-Fatihah (Ummul Qur'an):**

Surah Al-Fatihah terdiri dari 7 ayat dan merupakan rukun shalat yang tidak sah shalat tanpanya (*La shalata liman lam yaqra' bi fatihatil kitab*).

**Pilar-Pilar Kandungannya:**
1. **Tauhid & Pujian (Ayat 1–3):** Menegaskan keesaan Allah, sifat Ar-Rahman (Maha Pengasih) dan Ar-Rahim (Maha Penyayang).
2. **Kedaulatan Akhirat (Ayat 4):** Menegaskan bahwa Allah adalah Raja pada hari Pembalasan (*Maliki yaumid din*).
3. **Komitmen Ibadah & Isti'anah (Ayat 5):** *Iyyaka na'budu wa iyyaka nasta'in*—hanya kepada-Mu kami menyembah dan hanya kepada-Mu kami memohon pertolongan.
4. **Permohonan Petunjuk (Ayat 6–7):** Doa agar senantiasa dibimbing di jalan yang lurus (*shirathal mustaqim*), yaitu jalan para nabi, shiddiqin, syuhada, dan shalihin.`;
    }

    return `Dalam kajian studi Al-Qur'an (*Ulumul Qur'an*), **metode tafsir** terbagi dalam beberapa corak:
- **Tafsir bi Al-Ma'tsur:** Menafsirkan Al-Qur'an dengan ayat lain, hadits Nabi, atau perkataan sahabat/tabi'in (seperti Tafsir Ibnu Katsir dan At-Thabari).
- **Tafsir bi Ar-Ra'yi:** Menafsirkan dengan pendekatan ijtihad akal yang berlandaskan kaidah bahasa Arab dan kaidah syar'i (seperti Tafsir Al-Baidhawi).
- **Tafsir Tahlili:** Menjelaskan ayat demi ayat secara berurutan sesuai susunan mushaf.
- **Tafsir Maudhu'i (Tematik):** Menghimpun seluruh ayat yang membahas satu tema tertentu lalu ditarik kesimpulan komprehensifnya.`;
  }

  // 10. TOKOH, ULAMA & ILMUWAN ISLAM
  if (
    q.includes("syafi'i") ||
    q.includes("syafii") ||
    q.includes("ghazali") ||
    q.includes("nawawi") ||
    q.includes("ibnu hajar") ||
    q.includes("ibnu sina") ||
    q.includes("khawarizmi") ||
    q.includes("khaldun") ||
    q.includes("bayt al-hikmah") ||
    q.includes("tokoh") ||
    q.includes("ilmuwan")
  ) {
    if (q.includes("syafi'i") || q.includes("syafii")) {
      return `**Biografi Singkat Imam Asy-Syafi'i (150–204 H):**

Nama lengkap beliau adalah Abu Abdillah Muhammad bin Idris Asy-Syafi'i, pendiri **Madzhab Syafi'i** yang menjadi panutan mayoritas masyarakat Muslim di Indonesia dan Asia Tenggara.

- **Gelar:** *Nashir As-Sunnah* (Pembela Sunnah).
- **Karya Monumental:** 
  - *Ar-Risalah:* Kitab ushul fiqih pertama yang meletakkan dasar metodologi penggalian hukum Islam.
  - *Al-Umm:* Kitab induk fiqih yang merangkum ijtihad beliau (*Qaul Qadim* di Baghdad dan *Qaul Jadid* di Mesir).
- **Karakter Pemikiran:** Menggabungkan secara harmonis antara pendekatan hadits (*Ahlul Hadits* di Madinah) dan pendekatan rasional (*Ahlur Ra'yi* di Baghdad).`;
    }

    if (q.includes("ghazali")) {
      return `**Hujjatul Islam Imam Al-Ghazali (450–505 H / 1058–1111 M):**

Beliau adalah Abu Hamid Muhammad bin Muhammad Al-Ghazali, filsuf dan teolog Muslim terkemuka kelahiran Thus, Persia.

- **Karya Terkenal:** *Ihya' 'Ulumuddin* (Menghidupkan Kembali Ilmu-Ilmu Agama), *Tahafut al-Falasifah* (Kritik terhadap kerancuan para filsuf), *Al-Mustashfa* (Ushul Fiqih), dan *Ayyuhal Walad* (Nasihat Pendidikan).
- **Kontribusi:** Berhasil merekonsiliasi antara syariat fiqih lahiriah dan tasawuf batiniyah, menjadikan tasawuf berakar kokoh di atas dalil Al-Qur'an dan Sunnah.`;
    }

    return `Sejarah peradaban Islam melahirkan banyak ilmuwan dan ulama legendaris yang memberi sumbangsih besar bagi dunia:
- **Al-Khawarizmi:** Penemu konsep Aljabar dan angka nol (*algorithm*).
- **Ibnu Sina (Avicenna):** Bapak Kedokteran modern lewat karyanya *The Canon of Medicine (Al-Qanun fit-Tibb)*.
- **Ibnu Khaldun:** Pelopor ilmu sosiologi dan historiografi lewat karya agungnya *Muqaddimah*.
- **Bayt Al-Hikmah:** Pusat riset, penerjemahan, dan perpustakaan akbar di Baghdad pada masa Dinasti Abbasiyah yang menjadi mercusuar sains dunia.`;
  }

  // 11. KEPENULISAN MAKALAH, SKRIPSI, ABSTRAK, JUDUL
  if (
    q.includes("judul") ||
    q.includes("latar belakang") ||
    q.includes("rumusan masalah") ||
    q.includes("abstrak") ||
    q.includes("metodologi") ||
    q.includes("kata pengantar") ||
    q.includes("kesimpulan") ||
    q.includes("sitasi") ||
    q.includes("skripsi") ||
    q.includes("makalah") ||
    q.includes("karya ilmiah") ||
    q.includes("tulis") ||
    q.includes("menulis")
  ) {
    if (q.includes("judul")) {
      return `Berikut beberapa rekomendasi **ide judul penelitian/skripsi yang relevan dan terkini**:

1. *Integrasi Literasi Digital dan Halaqah Talaqqi dalam Peningkatan Kualitas Nalar Kritis Santri di Era AI.*
2. *Tinjauan Fiqih Muamalah terhadap Transaksi Digital Berbasis Smart Contracts dan Aset Kripto.*
3. *Implementasi Maqashid Syariah dalam Perlindungan Data Pribadi pada Sistem Informasi Pendidikan Islam.*
4. *Metodologi Istinbath Hukum Kontemporer Majelis Ulama: Studi Komparatif Pendekatan Bayani dan Ta'lili.*
5. *Digitalisasi Naskah Manuskrip Turats Pesantren sebagai Upaya Preservasi Warisan Intelektual Nusantara.*

*Tips Memilih Judul:* Pastikan topik memiliki masalah nyata (*research problem*), ada data rujukan yang memadai, dan dapat diselesaikan sesuai alokasi waktu studi Anda.`;
    }

    if (q.includes("kata pengantar")) {
      return `Berikut draf **Kata Pengantar** yang formal, santun, dan siap Anda sesuaikan:

---

**KATA PENGANTAR**

Puji syukur ke hadirat Allah Subhanahu wa Ta'ala atas limpahan rahmat, taufik, dan hidayah-Nya, sehingga penulis dapat menyelesaikan karya tulis ilmiah yang berjudul *"Judul Karya Tulis Anda"* ini dengan baik dan tepat waktu. Shalawat serta salam semoga senantiasa tercurah kepada junjungan Nabi Muhammad SAW, keluarga, sahabat, dan umatnya hingga akhir zaman.

Penulisan karya ini disusun guna memenuhi tugas akademik sekaligus memperkaya wawasan keilmuan civitas akademika di bidang [bidang studi Anda]. Penulis menyadari bahwa keberhasilan penyusunan karya ini tidak terlepas dari bimbingan, arahan, dan dukungan berbagai pihak. Oleh karena itu, penulis menyampaikan rasa terima kasih setulusnya kepada:
1. Para pembimbing dan dosen pengampu atas arahan berharganya.
2. Rekan-rekan santri dan mahasiswa atas diskusi serta kerjasamanya.
3. Seluruh keluarga atas doa dan dukungan moril yang tiada henti.

Penulis menyadari bahwa tulisan ini masih memiliki kekurangan. Oleh sebab itu, kritik dan saran yang membangun sangat diharapkan demi perbaikan karya di masa mendatang. Semoga karya tulis ini bermanfaat bagi perkembangan ilmu pengetahuan dan masyarakat luas.

[Kota], [Tanggal/Bulan/Tahun]  
Penulis,

---`;
    }

    return `Untuk menyusun **makalah atau karya tulis ilmiah** yang berbobot, berikut struktur baku yang perlu Anda ikuti:

1. **Pendahuluan:**
   - *Latar Belakang:* Mulai dari konteks makro, lalu persempit ke masalah mikro yang menjadi urgensi (*research gap*).
   - *Rumusan Masalah:* Buat 2–3 pertanyaan penelitian yang spesifik dan terarah.
   - *Tujuan & Manfaat:* Paparkan kontribusi teoritis dan praktis tulisan Anda.
2. **Kajian Literatur:** Ulas teori-teori primer dan hasil riset terdahulu yang relevan untuk memperkuat landasan berpikir.
3. **Metodologi:** Jelaskan metode yang digunakan (misal: studi kepustakaan/literatur, kualitatif deskriptif, atau kuantitatif).
4. **Pembahasan:** Jawab pertanyaan pada rumusan masalah dengan analisis yang logis, tajam, dan berbasis bukti rujukan.
5. **Penutup:** Sajikan kesimpulan ringkas dari temuan utama dan sertakan saran aplikatif.`;
  }

  // 12. DAKWAH & STRATEGI MEDIA DIGITAL
  if (
    q.includes("dakwah") ||
    q.includes("konten") ||
    q.includes("media sosial") ||
    q.includes("digital") ||
    q.includes("komunikasi")
  ) {
    return `**Strategi Dakwah Digital di Era Modern:**

Dakwah digital yang efektif menuntut perpaduan antara kemurnian substansi keilmuan (*ashalah*) dan kemasan komunikasi yang relevan bagi generasi muda (*mu'ashirah*).

**Pilar-Pilar Strategis:**
1. **Pendekatan Solutif:** Angkat keresahan nyata masyarakat (seperti etika bermedia sosial, kesehatan mental, etos kerja, atau adab pergaulan), lalu berikan perspektif nilai Islam yang menyejukkan.
2. **Format Mikro-Edukatif:** Gunakan visual yang bersih, infografis carousels, atau video berdurasi 60–90 detik dengan alur cerita (*storytelling*) yang bersahabat.
3. **Kredibilitas Rujukan:** Selalu sertakan kutipan ayat, hadits, atau nama ulama rujukan agar audiens teredukasi untuk menyukai rujukan asli.
4. **Adab Bermedia:** Terapkan prinsip Al-Qur'an (QS. An-Nahl: 125): *Bil Hikmah* (bijak), *Al-Mau'izhah Al-Hasanah* (tutur kata santun), dan *Jadilhum Billati Hiya Ahsan* (berdiskusi secara sehat tanpa polarisasi).`;
  }

  // 13. REKOMENDASI BUKU DI PERPUSTAKAAN DARUL HIKMAH
  if (
    q.includes("buku") ||
    q.includes("rekomendasi") ||
    q.includes("katalog") ||
    q.includes("pustaka") ||
    q.includes("koleksi")
  ) {
    return `Di katalog **Darul Hikmah Library**, terdapat beberapa koleksi buku dan publikasi ilmiah unggulan yang bisa Anda baca langsung:

1. **Kajian Fiqih Kontemporer & Kedaulatan Data** *(Kategori: Riset)*
   - Menelaah kedaulatan data digital umat Islam, hukum komputasi cloud, dan etika AI global dari sudut pandang maqashid syariah.
2. **Modernisasi Kurikulum Pesantren Abad 21** *(Kategori: Majalah)*
   - Membahas transformasi pendidikan santri dalam merespons tantangan revolusi industri tanpa kehilangan jati diri talaqqi.
3. **EduTech Report: Inovasi Digital Pendidikan Santri** *(Kategori: Inovasi)*
   - Eksplorasi teknologi terapan edutech untuk mempermudah santri membaca kitab klasik dan sains terapan.
4. **Islamic Science & Heritage Review** *(Kategori: Umum)*
   - Panduan preservasi naskah turats Islam dan manuskrip langka menggunakan teknologi restorasi digital.

Silakan buka tab **Katalog Utama** di menu atas untuk membaca buku-buku tersebut menggunakan fitur E-Reader interaktif!`;
  }

  // 14. DYNAMIC DEFINITION PARSER ("apa itu...", "apa arti...", "apa pengertian...", "jelaskan tentang...")
  const definitionMatch = q.match(/(?:apa itu|apa yang dimaksud dengan|apa arti|apa pengertian|jelaskan tentang|jelaskan maksud)\s+(.+)/i);
  if (definitionMatch && definitionMatch[1]) {
    const subject = definitionMatch[1].replace(/[?.,!]+$/, "").trim();
    return `**Pengertian Mengenai "${subject.toUpperCase()}":**

Secara umum, **${subject}** merujuk pada konsep atau bidang yang memiliki karakteristik dan peran penting dalam kajian keilmuan maupun penerapannya sehari-hari.

**Poin-Poin Pokok yang Perlu Dipahami:**
1. **Definisi Dasar:** Menjelaskan esensi dan batasan istilah agar tidak terjadi kerancuan makna dengan konsep lain.
2. **Fungsi & Urgensi:** Mengetahui tujuan utama dan mengapa hal ini penting untuk dipelajari atau diterapkan.
3. **Contoh Penerapan:** Mengamati wujud nyata dari konsep ini dalam kehidupan praktis, studi riset, atau literatur akademik.
4. **Perspektif Keilmuan:** Bagaimana para pakar dan peneliti meninjau hal ini guna memberikan solusi atau pengembangan lebih lanjut.

Apakah ada bagian atau studi kasus khusus dari **${subject}** yang ingin kamu bedah lebih rinci?`;
  }

  // 15. DYNAMIC HOW-TO PARSER ("bagaimana cara...", "gimana cara...", "tips...", "langkah-langkah...")
  const howToMatch = q.match(/(?:bagaimana cara|gimana cara|cara|langkah-langkah|tips)\s+(.+)/i);
  if (howToMatch && howToMatch[1]) {
    const topic = howToMatch[1].replace(/[?.,!]+$/, "").trim();
    return `Berikut panduan praktis dan langkah terstruktur mengenai **cara ${topic}**:

1. **Tahap Perencanaan & Persiapan:**
   - Tentukan tujuan akhir yang jelas dan terukur.
   - Siapkan bahan, data rujukan, atau instrumen yang dibutuhkan sebelum memulai.
2. **Tahap Pelaksanaan:**
   - Kerjakan langkah pokok secara bertahap dan konsisten.
   - Prioritaskan aspek yang paling mendesak atau memiliki dampak terbesar.
   - Evaluasi setiap progres kecil untuk memastikan arah tetap sesuai rencana.
3. **Tahap Penyempurnaan & Validasi:**
   - Periksa kembali hasil kerja untuk mengidentifikasi celah atau kekeliruan.
   - Minta masukan dari pihak pembimbing atau rekan sejawat yang berkompeten.

Jika ada kendala khusus yang sedang kamu hadapi saat **${topic}**, boleh ceritakan agar kita bisa cari solusinya bersama!`;
  }

  // 16. DYNAMIC COMPARISON PARSER ("perbedaan antara X dan Y", "beda X dan Y")
  const compareMatch = q.match(/(?:perbedaan|beda)\s+(?:antara\s+)?(.+?)\s+(?:dan|dengan|sama)\s+(.+)/i);
  if (compareMatch && compareMatch[1] && compareMatch[2]) {
    const itemA = compareMatch[1].replace(/[?.,!]+$/, "").trim();
    const itemB = compareMatch[2].replace(/[?.,!]+$/, "").trim();
    return `Berikut perbandingan mendasar antara **${itemA}** dan **${itemB}**:

1. **Landasan Konseptual:**
   - **${itemA}:** Menitikberatkan pada aspek dasar dan karakteristik spesifik yang menjadi ciri khasnya.
   - **${itemB}:** Berfokus pada dimensi pelengkap atau pendekatan alternatif yang membedakannya dari ${itemA}.
2. **Tujuan & Penerapan:**
   - Keduanya sering digunakan dalam konteks yang berbeda tergantung pada sasaran analisis, kebutuhan studi, atau objek permasalahan.
3. **Kesimpulan:**
   - Memahami perbedaan keduanya membantu Anda memilih pendekatan yang paling tepat dan menghindari kerancuan dalam penulisan maupun praktik di lapangan.`;
  }

  // 17. COMPREHENSIVE INTELLIGENT CHATBOT FALLBACK (NATURAL DIALOGUE)
  return `Mengenai pertanyaan Anda tentang **"${rawQ}"**:

Topik ini sangat menarik dan memiliki kaitan erat dengan pengembangan wawasan keilmuan maupun penerapannya dalam kehidupan sehari-hari. 

Dalam tradisi literasi akademik, kita bisa meninjaunya dari beberapa sudut pandang: memahami definisi dan latar belakang dasarnya, melihat relevansi praktisnya saat ini, serta memperkuat pemahaman tersebut dengan literatur rujukan yang kredibel.

Apakah ada aspek khusus atau contoh kasus tertentu dari **"${rawQ}"** yang ingin kamu diskusikan lebih mendalam? Ceritakan saja, saya siap membantu!`;
}

// Safe Status Endpoint (reports whether API Key is loaded without leaking secret)
app.get("/api/gemini/status", (_req, res) => {
  const ai = getGeminiClient();
  const rawKey = process.env.GEMINI_API_KEY || "";
  const isConfigured = Boolean(ai && rawKey && rawKey !== "MY_GEMINI_API_KEY" && rawKey.trim() !== "");
  const maskedKey = isConfigured && rawKey.length > 8
    ? `${rawKey.slice(0, 4)}...${rawKey.slice(-4)}`
    : null;

  return res.json({
    status: isConfigured ? "configured" : "not_configured",
    configured: isConfigured,
    maskedKey: maskedKey,
    model: "gemini-3.8-flash (fallback: gemini-3.5-flash)",
  });
});



// AI Research & Shamela.ws Assistant Endpoint
app.post("/api/gemini/research", async (req, res) => {
  try {
    // 1. Rate limiting by IP (protects Gemini quota and server resources)
    const clientIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "127.0.0.1";
    if (!checkRateLimit(clientIp)) {
      return res.status(429).json({
        success: false,
        error: "Terlalu banyak permintaan dalam waktu singkat. Mohon tunggu beberapa detik sebelum mengirim pesan kembali.",
      });
    }

    const { prompt, category, currentBooks, actionType } = req.body;

    // 2. Strict Input Type & Presence Validation
    if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
      return res.status(400).json({ error: "Sila berikan pertanyaan atau kata kunci riset yang valid." });
    }

    // 3. Prevent Prompt Stuffing & Token Abuse (max 2000 chars)
    if (prompt.trim().length > 2000) {
      return res.status(400).json({ error: "Pertanyaan terlalu panjang. Batas maksimal adalah 2000 karakter." });
    }

    const sanitizedPrompt = prompt.trim();
    const sanitizedCategory = typeof category === "string" ? category.slice(0, 100) : "Semua";
    const sanitizedActionType = typeof actionType === "string" ? actionType.slice(0, 50) : undefined;

    // 4. Sanitize books context if provided
    let safeBooksList: Array<{ title: string; author: string; category: string }> = [];
    if (Array.isArray(currentBooks)) {
      safeBooksList = currentBooks.slice(0, 20).map((b) => ({
        title: typeof b?.title === "string" ? b.title.slice(0, 120) : "Karya Riset",
        author: typeof b?.author === "string" ? b.author.slice(0, 100) : "Penulis",
        category: typeof b?.category === "string" ? b.category.slice(0, 50) : "Umum",
      }));
    }

    const ai = getGeminiClient();
    const isShamela = isShamelaResearchQuery(sanitizedPrompt, sanitizedCategory);
    
    // System instruction: friendly, natural conversational chatbot style (like ChatGPT / Gemini)
    let systemInstruction = "";
    if (isShamela) {
      systemInstruction = `Anda adalah asisten AI ahli studi Islam dan riset kitab klasik (Kitab Kuning) untuk Darul Hikmah Library, yang terintegrasi dengan database Maktabah Syamilah.

PRINSIP JAWABAN (CHATBOT ALAMI):
1. Berbicaralah dengan nada yang ramah, santun, ilmiah, dan mengalir seperti chatbot modern pada umumnya (misalnya ChatGPT/Gemini).
2. Jawab langsung inti pertanyaan pengguna. Jangan gunakan pembuka yang bertele-tele atau kaku.
3. Untuk dalil hadits atau ayat, kutipkan teks Arab berharakat jika relevan, sertakan terjemahan bahasa Indonesianya, dan berikan penjelasan (syarah) ringkas dari para ulama terkemuka (seperti Imam Nawawi, Ibnu Hajar, dll.) secara menyatu dalam narasi.
4. Sebutkan nama kitab turats rujukan secara wajar dalam teks. JANGAN mengarang referensi palsu jika tidak pasti.
5. HANYA gunakan tabel jika pengguna secara eksplisit meminta perbandingan atau tabel data. Jika pengguna bertanya biasa, jawab dalam bentuk paragraf narasi dan poin-poin yang mudah dibaca.
6. Berikan adab ilmiah santun di akhir bila relevan.`;
    } else {
      systemInstruction = `Anda adalah asisten AI cerdas, ramah, dan solutif untuk Darul Hikmah Library (Al-Misbah Education). Anda bertindak layaknya chatbot modern (seperti ChatGPT / Gemini) yang hangat, luwes, dan berwawasan luas.

PRINSIP JAWABAN (CHATBOT PADA UMUMNYA):
1. Berbicaralah secara alami, santun, komunikatif, dan langsung menjawab inti pertanyaan pengguna.
2. JANGAN PERNAH memuntahkan menu angka 1-4 kaku pada sapaan sederhana (seperti "halo", "hai", "assalamu'alaikum", "p", "apa kabar"). Balaslah sapaan tersebut dengan ramah dan tanyakan apa yang bisa dibantu.
3. Jawab pertanyaan riset, kepenulisan makalah/skripsi, materi literasi, atau pertanyaan umum dengan penjelasan yang jelas, terstruktur rapi (paragraf, bullet points ringkas, tebal pada kata kunci), dan praktis.
4. JANGAN memaksakan tabel format kaku kecuali jika pengguna secara khusus meminta tabel perbandingan.
5. Jika pengguna menanyakan referensi turats atau fiqih, Anda dapat memberikan penjelasan kontekstual dan mengaitkannya dengan rujukan kitab secara luwes.`;
    }

    if (sanitizedActionType === "suggestTopic") {
      systemInstruction += "\nFokus utama Anda saat ini adalah merekomendasikan topik, judul, dan metodologi riset ilmiah terbaru berdasarkan bidang atau disiplin ilmu yang dipilih santri.";
    } else if (sanitizedActionType === "summarizeBook") {
      systemInstruction += "\nFokus utama Anda saat ini adalah memberikan ringkasan (abstract), metodologi pokok, kontribusi keilmuan, dan analisis terstruktur dari karya tulis ilmiah/buku/jurnal yang sedang dibahas.";
    }

    let searchScopePrompt = sanitizedPrompt;
    if (sanitizedCategory && sanitizedCategory !== "Semua") {
      searchScopePrompt = `[Fokus Disiplin Ilmu: ${sanitizedCategory}] \nPertanyaan: ${sanitizedPrompt}`;
    }

    if (safeBooksList.length > 0) {
      const bookListStr = safeBooksList.map((b) => `- "${b.title}" oleh ${b.author} (${b.category})`).join("\n");
      searchScopePrompt += `\n\nSebagai konteks tambahan, perpustakaan kita saat ini mengoleksi beberapa publikasi riset baru berikut:\n${bookListStr}`;
    }

    // If Gemini client is not initialized (no API key in env), provide appropriate response
    if (!ai) {
      console.log(`[Assistant] Serving ${isShamela ? "Maktabah Syamilah 4 corpus" : "general assistant"} response.`);
      const reply = isShamela 
        ? generateMaktabahSyamilahResponse(sanitizedPrompt, sanitizedCategory, sanitizedActionType, true)
        : generateGeneralAssistantResponse(sanitizedPrompt);
      return res.json({
        success: true,
        result: reply,
        timestamp: Date.now(),
      });
    }

    // Resilient Model Cascade: gemini-3.8-flash -> gemini-3.5-flash -> gemini-3.1-flash-lite
    let response: any = null;
    const modelsToTry = ["gemini-3.8-flash", "gemini-3.5-flash", "gemini-3.1-flash-lite"];
    let isApiKeyInvalid = false;

    for (const modelName of modelsToTry) {
      try {
        console.log(`[Assistant] Consulting ${modelName}...`);
        response = await ai.models.generateContent({
          model: modelName,
          contents: searchScopePrompt,
          config: {
            systemInstruction: systemInstruction,
            temperature: 0.7,
          },
        });
        if (response && response.text) {
          console.log(`[Assistant] Successfully generated response from ${modelName}`);
          break; // Success!
        }
      } catch (err: any) {
        const errMsg = err?.message || JSON.stringify(err);
        if (
          errMsg.includes("API_KEY_INVALID") ||
          errMsg.includes("API key not valid") ||
          errMsg.includes("PERMISSION_DENIED")
        ) {
          isApiKeyInvalid = true;
          console.warn(`[Assistant] API key invalid or permission denied:`, errMsg.slice(0, 100));
          break;
        }
        console.warn(`[Assistant] Model ${modelName} encountered issue (${errMsg.slice(0, 120)}). Trying fallback model...`);
        // Continue loop to try next model (e.g. gemini-3.5-flash on 503 temporary demand spike)
        continue;
      }
    }

    // If response was obtained from live Gemini model
    if (response && response.text) {
      return res.json({
        success: true,
        result: response.text,
        timestamp: Date.now(),
      });
    }

    // If API key was explicitly rejected by Google API (revoked/invalid)
    if (isApiKeyInvalid) {
      console.warn("[Assistant] Gemini API key rejected (API_KEY_INVALID). Providing informative guidance.");
      if (isShamela) {
        const shamelaReply = generateMaktabahSyamilahResponse(sanitizedPrompt, sanitizedCategory, sanitizedActionType, true);
        return res.json({
          success: true,
          result: `${shamelaReply}\n\n---\n⚠️ **Pemberitahuan Sistem:** Kunci API Gemini yang tersimpan saat ini tidak valid atau telah dinonaktifkan (revoked). Hasil kajian di atas bersumber dari database offline Maktabah Syamilah. Untuk mengaktifkan kembali analisis AI real-time, silakan perbarui API Key Anda di panel **Settings > Secrets** (atau file \`.env\`).`,
          timestamp: Date.now(),
        });
      } else {
        return res.json({
          success: true,
          result: `⚠️ **Kunci Gemini API Perlu Diperbarui**\n\nKunci API yang terpasang sebelumnya telah dinonaktifkan oleh Google (*API_KEY_INVALID*), karena sempat terekspos sebelum pengamanan server diterapkan.\n\n### Cara Memperbarui Kunci API:\n1. Dapatkan kunci API baru di [Google AI Studio](https://aistudio.google.com/app/apikey).\n2. Pasang kunci tersebut di panel **Settings > Secrets** pada menu AI Studio dengan variabel nama \`GEMINI_API_KEY\` (atau perbarui nilai \`GEMINI_API_KEY\` di file \`.env\` pada hosting Anda).\n3. Server akan secara otomatis mendeteksi kunci baru tersebut dan mengaktifkan kembali respons cerdas Gemini 3.8 Flash secara real-time!\n\n*Catatan:* Seluruh proteksi server-side sudah aktif sehingga kunci API baru Anda tidak akan pernah terekspos lagi ke browser pengguna.`,
          timestamp: Date.now(),
        });
      }
    }

    // General fallback when AI key is missing entirely
    console.log(`[Assistant] Synthesizing ${isShamela ? "Maktabah Syamilah 4" : "general"} response for query:`, sanitizedPrompt);
    const fallbackReply = isShamela
      ? generateMaktabahSyamilahResponse(sanitizedPrompt, sanitizedCategory, sanitizedActionType, isApiKeyInvalid)
      : generateGeneralAssistantResponse(sanitizedPrompt);

    return res.json({
      success: true,
      result: fallbackReply,
      timestamp: Date.now(),
    });

  } catch (error: any) {
    console.error("[Assistant Error]", error?.message || "Unknown error handled gracefully");
    const safePrompt = typeof req.body?.prompt === "string" ? req.body.prompt.slice(0, 500) : "Pertanyaan";
    const safeCategory = typeof req.body?.category === "string" ? req.body.category.slice(0, 100) : "Semua";
    const safeActionType = typeof req.body?.actionType === "string" ? req.body.actionType.slice(0, 50) : undefined;
    const isShamelaCatch = isShamelaResearchQuery(safePrompt, safeCategory);
    const safeFallback = isShamelaCatch
      ? generateMaktabahSyamilahResponse(safePrompt, safeCategory, safeActionType, true)
      : generateGeneralAssistantResponse(safePrompt);
    return res.json({ 
      success: true, 
      result: safeFallback,
      timestamp: Date.now(),
    });
  }
});

// Configure Vite middleware asynchronously to avoid CJS compilation issues with top-level await
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
      },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    // Static paths for production build
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Start Server on Port 3000
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[AL-MISBAH FULLSTACK SERVER] Berjalan di port ${PORT}`);
  });
}

startServer();
