# Pemulihan Login License Manager

1. Deploy ZIP ini ke repository/deployment License Manager saja. Jangan timpa Developer Console atau SIMPATI 555 LIVE.
2. Pastikan `DATABASE_URL` menunjuk ke database License Manager yang sama dengan deployment aktif. Jangan mengubah URL database jika belum diverifikasi.
3. Setelah deploy, buka terminal/console proyek License Manager dan jalankan `python scripts/reset_superadmin.py`. Masukkan username dan password baru secara interaktif. Password tidak ditulis di command history.
4. Restart/redeploy License Manager. Periksa log startup: kolom `package_modules.is_mandatory` harus berhasil ditambahkan dan akun Superadmin harus tersimpan.
5. Isi `LICENSE_MANAGER_USERNAME` dan `LICENSE_MANAGER_PASSWORD` di Developer Console dengan kredensial yang sama, lalu restart Developer Console.

Catatan: script reset mengubah hanya satu akun berdasarkan username pada database yang dikonfigurasi. Script tidak menghapus data lisensi/pelanggan. Perubahan kode telah diperiksa sintaks Python, tetapi login sungguhan tetap harus diverifikasi pada Hostless karena memerlukan akses ke database dan deployment aktual.
