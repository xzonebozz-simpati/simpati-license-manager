# Panduan Deployment Staging SIMPATI LICENSE MANAGER
## Infrastruktur: Hostless (App Platform) + Supabase (PostgreSQL)

Dokumentasi ini berisi langkah-langkah terstruktur untuk melakukan deployment **SIMPATI LICENSE MANAGER** ke lingkungan **Staging** menggunakan platform cloud **Hostless** dan basis data relasional **Supabase PostgreSQL**.

---

### 1. Ringkasan Arsitektur Staging

| Komponen | Spesifikasi / Layanan | Keterangan |
| :--- | :--- | :--- |
| **Aplikasi Server** | FastAPI (Python 3.11+) | Dijalankan sebagai container/web service di **Hostless** |
| **Web Server / ASGI**| Uvicorn | Port otomatis mendeteksi environment variable `PORT` dari Hostless |
| **Reverse Proxy** | Hostless Ingress / Cloudflare | Menangani SSL/HTTPS termination; di-trust via `ProxyHeadersMiddleware` |
| **Database** | Supabase PostgreSQL (15+) | Dedicated instance untuk License Manager (terpisah dari DB SIMPATI 555) |
| **ORM & Migrasi** | SQLAlchemy 2.0 + Alembic | Migrasi otomatis dijalankan via release phase atau perintah manual |
| **Kriptografi** | Ed25519 Digital Signature | Private key dibaca dari Environment Secret (tidak disimpan di file git) |

---

### 2. Langkah 1: Persiapan Database Supabase

1. Buka dashboard [Supabase](https://supabase.com) dan buat proyek baru (misal: `simpati-license-staging`).
2. Masuk ke menu **Project Settings** > **Database**.
3. Dapatkan **Connection String** (URI). Terdapat 2 opsi:
   * **Opsi A (Direct Connection - Port 5432)**:
     ```text
     postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres?sslmode=require
     ```
   * **Opsi B (PgBouncer Transaction Pooler - Port 6543 - Direkomendasikan untuk Serverless/Container)**:
     ```text
     postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?sslmode=require
     ```
4. Catat URI tersebut untuk dimasukkan ke variabel `DATABASE_URL` di Hostless.

---

### 3. Langkah 2: Pembuatan Kunci Kriptografis Ed25519 (Digital Signature)

Private key Ed25519 **wajib** disiapkan di environment secret agar License Manager dapat menandatangani respons verifikasi lisensi SIMPATI 555 tanpa bergantung pada file disk.

Jalankan perintah one-liner Python berikut di terminal lokal untuk men-generate keypair baru:

```bash
python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from cryptography.hazmat.primitives import serialization; k = Ed25519PrivateKey.generate(); priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode().replace('\n', '\\n'); pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode().replace('\n', '\\n'); print('--- SALIN UNTUK ED25519_PRIVATE_KEY_PEM ---'); print(priv); print('\n--- SALIN UNTUK ED25519_PUBLIC_KEY_PEM (OPSIONAL) ---'); print(pub)"
```

Simpan output string `ED25519_PRIVATE_KEY_PEM` dengan aman. **Jangan pernah meng-commit private key ini ke Git.**

---

### 4. Langkah 3: Konfigurasi Environment Variables di Hostless

Pada dashboard proyek Hostless, masuk ke menu **Environment Variables / Secrets** dan tambahkan variabel berikut:

| Nama Variabel | Contoh Nilai | Keterangan |
| :--- | :--- | :--- |
| `APP_ENV` | `staging` | Mode staging (mengaktifkan secure cookie) |
| `APP_DEBUG` | `false` | Matikan debug log di staging |
| `SECRET_KEY` | *(acak 64 karakter hex)* | Kunci JWT session & CSRF (`python -c "import secrets; print(secrets.token_hex(32))"`) |
| `DATABASE_URL` | `postgresql://postgres:[PASS]@db...:5432/postgres?sslmode=require` | Connection string PostgreSQL Supabase |
| `ED25519_PRIVATE_KEY_PEM` | `"-----BEGIN PRIVATE KEY-----\nMC4CAQAwB...-----END PRIVATE KEY-----"` | Private key untuk tanda tangan digital lisensi |
| `ADMIN_USERNAME` | `superadmin` | Username Superadmin awal |
| `ADMIN_PASSWORD` | *(password kuat)* | Password Superadmin awal |
| `ADMIN_EMAIL` | `admin@simpati555.id` | Email Superadmin awal |
| `FORWARDED_ALLOW_IPS` | `*` | Mempercayai header reverse proxy Hostless |
| `CORS_ORIGINS` | `https://simpati.id,http://localhost:8000` | Domain instans yang berhak akses CORS |

> **Catatan Port:** Hostless secara otomatis menyuntikkan variabel `PORT`. Aplikasi sudah dikonfigurasi untuk membaca port dinamis tersebut secara otomatis.

---

### 5. Langkah 4: Konfigurasi Build & Perintah Startup

Aplikasi telah dilengkapi file `Procfile` di root direktori:

```text
web: python app.py
release: python -m alembic upgrade head
```

* **Buildpack / Runtime**: Python 3.11+
* **Build Command**: `pip install -r requirements.txt`
* **Release Command (Migrasi Otomatis)**:
  Jika platform Hostless mendukung release phase, jalankan:
  ```bash
  python -m alembic upgrade head
  ```
  *Jika Hostless tidak memiliki fitur release phase, perintah migrasi dapat dijalankan sekali melalui Hostless Web Console / SSH, atau sistem akan otomatis memvalidasi skema melalui lifespan startup `Base.metadata.create_all()`.*
* **Start Command**:
  ```bash
  python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips "*"
  ```

---

### 6. Langkah 5: Verifikasi Pasca-Deployment

Setelah deployment selesai di Hostless, lakukan pemeriksaan endpoint berikut menggunakan domain publik staging Anda (misal `https://license-staging.hostless.app`):

#### 1. Uji Liveness Probe
```bash
curl -i https://license-staging.hostless.app/healthz
```
*Respons yang diharapkan:* HTTP `200 OK` dengan metadata status `"ok"`.

#### 2. Uji Readiness & Koneksi Database Supabase
```bash
curl -i https://license-staging.hostless.app/api/v1/health/db
```
*Respons yang diharapkan:*
```json
{
  "status": "connected",
  "dialect": "postgresql",
  "latency_ms": 42.15,
  "tables_registered": 24,
  "error": null
}
```

#### 3. Uji Pengambilan Root Public Key
```bash
curl -i https://license-staging.hostless.app/api/v1/licenses/root-public-key
```
*Respons yang diharapkan:* HTTP `200 OK` berisi `public_key_pem` yang valid dan siap diverifikasi oleh SIMPATI 555.

#### 4. Uji Akses Web Dashboard
Buka `https://license-staging.hostless.app/login` di peramban, lalu login menggunakan kredensial Superadmin yang telah dikonfigurasi di `ADMIN_USERNAME` dan `ADMIN_PASSWORD`.

---

### 7. Checklist Tindakan Pemilik Akun (Action Items)

- [ ] **Buat Database Supabase**: Buat project database baru di Supabase khusus untuk License Manager.
- [ ] **Salin Connection String Supabase**: Tambahkan parameter `?sslmode=require` pada URL PostgreSQL.
- [ ] **Generate Ed25519 Secret**: Jalankan skrip Python di langkah 3 dan salin string private key.
- [ ] **Set Environment Variables**: Masukkan seluruh variabel tabel Langkah 3 ke dashboard Hostless.
- [ ] **Deploy Branch**: Lakukan trigger deploy pada branch `feat/client-integration-support`.
- [ ] **Jalankan Migrasi**: Pastikan `python -m alembic upgrade head` telah berjalan di database Supabase.
- [ ] **Login & Ganti Password**: Masuk ke dashboard dan pastikan akun Superadmin aktif.
