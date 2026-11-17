# SIMPATI LICENSE MANAGER

Sistem Pusat Pengelolaan Lisensi Komersial Terpadu untuk Aplikasi **SIMPATI 555**.

---

## 1. Ringkasan Sistem & Model Bisnis

**SIMPATI LICENSE MANAGER** adalah aplikasi independen yang bertugas mengelola hak cipta, penerbitan lisensi komersial, aktivasi instalasi server, pemantauan masa berlaku, dan validasi berkala bagi seluruh pelanggan organisasi SIMPATI 555.

### Ketentuan Lisensi:
1. **Pemisahan Sistem & Data:**
   - Server, database, dokumen, dan data organisasi pelanggan tetap menjadi milik dan tanggung jawab penuh pelanggan.
   - License Manager **TIDAK** mengakses atau menyimpan data internal organisasi (data anggota, dokumen rahasia, akun operasional SIMPATI 555).
2. **Snapshot Entitlements:**
   - Hak lisensi yang diberikan kepada pelanggan disimpan sebagai **snapshot statis** bertanda tangan digital saat penerbitan lisensi. Perubahan katalog paket di masa depan tidak otomatis merusak atau mengubah hak lisensi aktif pelanggan.
3. **Mekanisme Grace Period & Restricted Mode:**
   - Ketika masa berlaku lisensi berakhir atau verifikasi berkala tertunda, sistem memasuki **Masa Tenggang (Grace Period)** selama 7 hari kalender.
   - Jika masa tenggang habis, SIMPATI masuk ke **Restricted Mode**:
     - Pengguna tetap dapat login, membaca seluruh data, melihat laporan, serta mengunduh backup data organisasi.
     - Penambahan, pengubahan, penghapusan data, perubahan hak akses, survei, dan upload diblokir untuk menjaga integritas kepatuhan lisensi.
     - **Prinsip Utama:** Keterlambatan administrasi tidak boleh membuat pelanggan kehilangan akses terhadap datanya sendiri.

---

## 2. Struktur Direktori Proyek

```
simpati-license-manager/
├── app/
│   ├── __init__.py
│   ├── main.py                     # Factory FastAPI, lifespan & security middleware (CSRF + Web Guard)
│   ├── config.py                   # Pydantic Settings & environment variables loader
│   ├── database/
│   │   ├── __init__.py
│   │   ├── connection.py           # Engine SQLAlchemy 2.x & connection latency check
│   │   └── session.py              # SessionLocal factory & get_db dependency
│   ├── models/
│   │   ├── __init__.py             # Agregator 24 model skema database
│   │   ├── base.py                 # DeclarativeBase, UUIDMixin, TimestampMixin
│   │   ├── user.py                 # LicenseUser, LicenseUserSession
│   │   ├── customer.py             # Customer (Organisasi Pelanggan)
│   │   ├── installation.py         # Installation, InstallationCredential, InstallationEvent
│   │   ├── catalog.py              # LicensePackage, ModuleRegistry, ModuleDependency, PackageModule
│   │   ├── license.py              # License, LicenseInstallation, LicenseModule, LicenseCapacity
│   │   ├── region.py               # Region, LicenseRegion, LicenseOrganizationalLevel
│   │   ├── security.py             # SigningKey, RevocationRecord, ApiSecurityLog
│   │   └── operations.py           # LicenseValidation, LicenseHistory, LicenseAuditLog, SystemSetting
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── health.py               # Schema healthz & db diagnostic
│   │   ├── auth.py                 # Schema login & session
│   │   ├── customer.py             # Schema CRUD pelanggan & relasi
│   │   ├── installation.py         # Schema instalasi, kredensial, detail, & telemetry heartbeat
│   │   ├── package.py              # Schema katalog paket, tier, modul, & konfigurasi komersial
│   │   └── license.py              # Schema lisensi, snapshot, perpanjangan, status, & verifikasi Ed25519
│   ├── security/
│   │   ├── __init__.py
│   │   ├── hashing.py              # Argon2id password hashing & verification
│   │   ├── crypto.py               # Ed25519 digital signature, token & key generation
│   │   ├── csrf.py                 # Proteksi CSRF (Double Submit Cookie & Exemption)
│   │   ├── tokens.py               # Session tokens & expiry calculation
│   │   └── dependencies.py         # FastAPI security dependencies (Superadmin & Web User guard)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── audit_service.py        # Centralized audit logger
│   │   ├── auth_service.py         # Login, logout & session lifecycle
│   │   ├── customer_service.py     # Customer management & relational integrity guard
│   │   ├── installation_service.py # Installation lifecycle, API credentials, & telemetry
│   │   ├── package_service.py      # Katalog paket, bundel modul, & konfigurasi komersial
│   │   ├── license_service.py      # Penerbitan, perpanjangan, status, snapshot, & Ed25519 signature
│   │   └── validation_service.py   # Periodic validation & Restricted Mode evaluator
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── health.py               # /healthz & /api/v1/health/db
│   │   ├── web.py                  # Antarmuka Jinja2 Dashboard & seluruh 10 menu (login-guarded)
│   │   └── api_v1/
│   │       ├── __init__.py
│   │       ├── auth.py             # Endpoints login & logout
│   │       ├── customers.py        # Endpoints data & relasi pelanggan
│   │       ├── installations.py    # Endpoints server instalasi, credentials, key, & heartbeat
│   │       ├── packages.py         # Endpoints katalog paket komersial & modul
│   │       ├── licenses.py         # Endpoints lisensi, perpanjangan, status, & verifikasi kripto
│   │       └── validations.py      # Endpoints verifikasi berkala instance SIMPATI
│   ├── templates/                  # Template HTML Jinja2 (Bahasa Indonesia & Tema Maroon-Emas)
│   │   ├── base.html               # Layout dasar, navigasi 10 menu, dan header status
│   │   ├── login.html              # Gerbang login aman Superadmin
│   │   ├── dashboard.html          # Overview ringkasan, kartu KPI, dan aksi cepat
│   │   ├── customers.html          # Manajemen Pelanggan + Modal Tambah/Edit/Detail/Hapus
│   │   ├── installations.html      # Manajemen Instalasi Server, Detail, Kredensial, & Heartbeat
│   │   ├── packages.html           # Katalog Paket Lisensi, Modal Tambah/Edit/Detail, Toggle Status
│   │   ├── modules.html            # Registry Modul SIMPATI & Dependencies
│   │   ├── licenses.html           # Manajemen Lisensi, Modal Terbitkan/Detail/Perpanjang/Status
│   │   ├── validations.html        # Riwayat Validasi Kriptografis Online
│   │   ├── history.html            # Audit Transisi Siklus Hidup Lisensi
│   │   ├── audit.html              # Jejak Audit Aktivitas Administratif
│   │   └── settings.html           # Konfigurasi Sistem & Kunci Digital Ed25519
│   └── static/
│       ├── css/
│       │   └── theme.css           # Tema mewah Maroon & Emas (Responsive UI & Modals)
│       └── js/
│           └── app.js              # Handler modal, aksi form, rotasi kredensial, filter dinamis & kripto
├── migrations/                     # Konfigurasi & versi migrasi Alembic
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── e56e8b3ae174_initial_schema_foundation.py
├── scripts/
│   ├── init_db.py                  # Inisialisasi skema & penyemaian data awal
│   └── generate_keys.py            # Generator pasangan kunci Ed25519
├── tests/                          # Pengujian otomatis Pytest (38 Test Cases)
│   ├── conftest.py                 # Fixtures test client & in-memory database
│   ├── test_auth_flow.py           # Pengujian alur autentikasi web & session
│   ├── test_customer_module.py     # Pengujian modul pelanggan & integritas relasi
│   ├── test_installation_module.py # Pengujian modul instalasi, kredensial, key, & heartbeat
│   ├── test_license_package_module.py # Pengujian katalog paket & lisensi komersial (Iterasi 5)
│   ├── test_health.py              # Pengujian endpoint kesehatan & koneksi DB
│   ├── test_security.py            # Pengujian Argon2id & Ed25519
│   ├── test_models.py              # Pengujian skema 24 tabel & relasi UUID
│   └── test_services.py            # Pengujian status lisensi, grace period & HTML views
├── alembic.ini
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── app.py                          # Runner aplikasi utama
```

---

## 3. Spesifikasi Keamanan & Kriptografi Lisensi

- **Autentikasi & Gerbang Masuk:** Seluruh dashboard dan menu manajemen dilindungi otentikasi sesi Superadmin. Pengunjung tanpa sesi aktif diarahkan ke portal login `/login`.
- **Password Hashing:** Menggunakan **Argon2id** (`argon2-cffi`) dengan parameter standar industri (`m=65536, t=3, p=4`).
- **Proteksi CSRF (Cross-Site Request Forgery):** Dilengkapi token CSRF berbasis cookie dan header `X-CSRF-Token` pada seluruh mutasi data (POST, PUT, PATCH, DELETE). Endpoint machine-to-machine seperti validasi lisensi dan heartbeat instalasi dikecualikan secara terukur.
- **Tanda Tangan Digital Lisensi Asimetris (Ed25519):**
  - Setiap lisensi yang diterbitkan atau diperpanjang ditandatangani secara digital oleh License Manager pusat menggunakan algoritma asimetris **Ed25519**.
  - Tanda tangan digital memuat canonical JSON snapshot hak akses pelanggan, instalasi terkait, daftar modul, tingkat organisasi, dan batas kapasitas.
  - Kunci privat penandatanganan hanya disimpan di sisi server License Manager pusat dan **TIDAK PERNAH** dikirimkan ke instalasi pelanggan.
  - Perubahan katalog paket di masa depan **tidak akan pernah** mengubah atau merusak hak akses lisensi yang sudah diterbitkan (*Immutability of Snapshot Entitlements*).
- **CRL (Certificate Revocation List):** Pencabutan permanen lisensi (`REVOKED`) otomatis dicatat ke dalam tabel `revocation_records` dan histori siklus hidup `license_history` beserta alasan administratif wajib.

---

## 4. Panduan Instalasi dan Menjalankan di Windows

### Persyaratan:
- Windows 10/11 atau Windows Server 2019/2022.
- Python 3.11 atau yang lebih baru.
- PostgreSQL 14/15/16 (atau SQLite untuk uji coba lokal mandiri tanpa server DB aktif).

### Langkah 1: Buka Terminal (PowerShell / Command Prompt)
Masuk ke direktori proyek:
```powershell
cd "c:\Users\Jasahary\Downloads\SIMPATI LICENSE MANAGER"
```

### Langkah 2: Buat Virtual Environment (Opsional namun Disarankan)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Langkah 3: Install Dependensi
```powershell
pip install -r requirements.txt
```

### Langkah 4: Konfigurasi Environment Variables (`.env`)
Salin file template `.env.example` menjadi `.env`:
```powershell
copy .env.example .env
```
Sesuaikan konfigurasi koneksi PostgreSQL Anda di dalam file `.env`:
```ini
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password_anda
DB_NAME=simpati_license_db
DATABASE_URL=postgresql+psycopg2://postgres:password_anda@localhost:5432/simpati_license_db
```
*(Catatan: Jika Anda ingin mencoba secara langsung tanpa menyiapkan server PostgreSQL terlebih dahulu, biarkan `DATABASE_URL=sqlite:///./simpati_license.db`).*

### Autentikasi server-to-server Universal API (Opsional)

Untuk mengaktifkan identitas layanan, simpan `UNIVERSAL_API_SERVICE_ID` dan
`UNIVERSAL_API_SERVICE_SECRET` sebagai Environment Variables/Secrets pada
deployment License Manager, lalu konfigurasi pasangan kredensial yang sama pada
deployment Universal API. Secret harus acak dengan panjang minimal 32 byte.
Jangan simpan kredensial ini di kode, Desktop, atau log; komunikasi HTTP Basic
hanya boleh dilakukan melalui HTTPS.

Identitas ini tidak membuat akun pengguna dan hanya dapat:

- Membaca daftar pelanggan.
- Membaca daftar paket, katalog modul, dan detail paket.
- Membaca daftar/detail lisensi, membuat lisensi, memperpanjang, mengubah masa
  berlaku, dan mengubah status lisensi.

Selama rotasi, pasang secret baru sebagai `UNIVERSAL_API_SERVICE_SECRET` dan
secret lama sebagai `UNIVERSAL_API_SERVICE_PREVIOUS_SECRET`. Setelah Universal
API memakai secret baru, hapus variabel previous secret lalu restart aplikasi.
Untuk mencabut seluruh akses layanan, hapus ID dan kedua secret dari environment
kemudian restart. Konfigurasi parsial atau secret yang terlalu pendek akan
membuat aplikasi gagal startup. Setiap permintaan layanan yang terotorisasi dan
perubahan lisensi dicatat dalam audit log dengan `service_id`.

### Langkah 5: Inisialisasi Database & Seeding Data Awal
Jalankan script inisialisasi:
```powershell
python scripts/init_db.py
```

### Langkah 6: Jalankan Aplikasi
Jalankan server menggunakan file runner:
```powershell
python app.py
```
Atau langsung melalui Uvicorn:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 5. Mengakses Antarmuka & Endpoint

Buka browser dan akses URL berikut:
- **Dashboard Web (Tema Maroon & Emas):** [http://localhost:8000/](http://localhost:8000/)
- **Kredensial Default Superadmin:**
  - **Username:** `superadmin`
  - **Password:** `SuperAdmin@2026!`
- **Swagger API Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc API Documentation:** [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Health Check Probe:** [http://localhost:8000/healthz](http://localhost:8000/healthz)

### Fitur Menu Dashboard:
1. **Dashboard:** Ringkasan KPI pelanggan, instalasi, lisensi, dan log aktivitas.
2. **Pelanggan:** Manajemen lengkap data organisasi, inspeksi detail & statistik relasi (instalasi & lisensi), edit data, aktivasi/penonaktifan (*Suspend*), dan penghapusan aman terlindungi integritas relasi.
3. **Instalasi:** Pendaftaran server deployment, pembuatan kode unik, penerbitan kredensial API Argon2id, pendaftaran public key Ed25519, rotasi kredensial, dan telemetry heartbeat.
4. **Paket Lisensi (Iterasi 5):**
   - Pembuatan dan pengubahan paket komersial.
   - Penentuan tier (`STARTER`, `PROFESSIONAL`, `ENTERPRISE`, `CUSTOM`).
   - Konfigurasi fleksibel: harga, periode lisensi, kapasitas bawaan anggota.
   - Penentuan bundel modul aplikasi dari master registry.
   - Penentuan tingkat organisasi default (`DPD`, `DPC`, `DPS`, `DPSS`).
   - Aktivasi dan penonaktifan paket.
5. **Modul:** Registry modul aplikasi SIMPATI 555 dan aturan dependensinya.
6. **Lisensi (Iterasi 5):**
   - Penerbitan lisensi komersial terikat pelanggan dan instalasi server.
   - Pembuatan snapshot entitlements statis bertanda tangan digital Ed25519.
   - Filter dinamis instalasi berdasarkan pelanggan yang dipilih.
   - Autofill otomatis modul dan kapasitas berdasarkan paket yang dipilih.
   - Inspeksi detail lisensi lengkap dengan verifikasi status tanda tangan kriptografis.
   - Perpanjangan masa berlaku lisensi (*extend/renew*) dengan re-signing otomatis.
   - Pengelolaan status lisensi (*Suspend*, *Reactivate*, *Revoke*) dengan pencatatan alasan wajib dan sinkronisasi ke tabel Revocation List (CRL).
   - Log jejak audit riwayat perubahan lisensi (`LicenseHistory`).
7. **Validasi:** Catatan pemeriksaan integritas token berkala secara online.
8. **Riwayat:** Jejak audit transisi siklus hidup lisensi (Issued, Renewed, Restricted).
9. **Audit Log:** Pencatatan aktivitas administratif dan keamanan sistem.
10. **Pengaturan:** Konfigurasi grace period, aturan restricted mode, dan info kunci Ed25519.

---

## 6. Pengujian Otomatis (Pytest)

Untuk memverifikasi keandalan kode, model, keamanan, dan endpoint:
```powershell
python -m pytest -v
```
Seluruh **38 pengujian** lulus 100%:
- `test_auth_flow.py` (6 test): Portal login Superadmin, otentikasi kata sandi Argon2id, cookie sesi, proteksi CSRF, proteksi rute dashboard, dan proses logout aman.
- `test_customer_module.py` (6 test): CRUD pelanggan, detail & statistik relasi, toggle status, serta proteksi penghapusan aman.
- `test_installation_module.py` (8 test): Pendaftaran instalasi, pencegahan duplikasi kode, identitas kriptografis API, pendaftaran public key Ed25519, siklus status & events, rotasi kredensial, telemetry heartbeat, dan proteksi relasi lisensi.
- `test_license_package_module.py` (6 test):
  - `test_package_crud_lifecycle`: Siklus hidup CRUD paket, penentuan modul, tingkat organisasi, dan toggle status.
  - `test_package_duplicate_code_fails`: Validasi integritas kode paket unik.
  - `test_issue_license_with_ed25519_signature`: Penerbitan lisensi terhubung instalasi pelanggan dan penandatanganan digital Ed25519.
  - `test_extend_license_and_re_signing`: Perpanjangan masa berlaku dan penandatanganan ulang snapshot.
  - `test_license_status_lifecycle_and_crl_revocation`: Perubahan status (Suspend/Reactivate/Revoke) dan pencatatan CRL.
  - `test_snapshot_immutability_on_package_change`: Verifikasi prinsip immutabilitas snapshot lisensi saat katalog paket berubah.
- `test_health.py` (2 test): Status kesehatan aplikasi (`/healthz`) dan diagnosa koneksi database (`/api/v1/health/db`).
- `test_models.py` (2 test): Integritas skema 24 tabel SQLAlchemy 2.x dengan UUID dan relasi cascade/guard.
- `test_security.py` (4 test): Hashing kata sandi Argon2id dan pembuatan tanda tangan digital Ed25519.
- `test_services.py` (4 test): Evaluasi komputasi status lisensi, grace period, restricted mode, dan integrasi view HTML.


---

## 7. Integrasi Klien SIMPATI 555

SIMPATI 555 (`pendaftaran555`) terhubung dengan License Manager melalui klien M2M `license_client.py`:

### Endpoint M2M Terlibat:
1. **Verifikasi Lisensi:** `POST /api/v1/validations/verify` (CSRF-exempt, Basic Auth dengan API client id/secret).
2. **Telemetri Heartbeat:** `POST /api/v1/installations/heartbeat` (pengiriman status ONLINE berkala).
3. **Root Public Key:** `GET /api/v1/licenses/root-public-key` (distribusi kunci publik Ed25519 untuk verifikasi signature snapshot secara offline).

### Penegakan di Sisi SIMPATI 555:
- **Restricted Mode:** Blokir otomatis pendaftaran baru, mutasi data anggota, pembuatan akun, dan upload dokumen saat lisensi kedaluwarsa/restricted.
- **Read & Export Preserved:** Akses baca data, pencarian wilayah, dan ekspor CSV/PDF tetap 100% aktif.
- **Kapasitas & Kuota:** Menjaga kuota maksimum anggota dan akun admin sesuai paket komersial.
- **Gating Modul:** Mengontrol aktivasi fitur berdasarkan modul yang dibeli (misal: `SURVEI_GPS`).
