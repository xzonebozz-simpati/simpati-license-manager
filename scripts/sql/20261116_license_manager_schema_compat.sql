-- SIMPATI License Manager - kompatibilitas skema (aman dijalankan berulang).
-- Jalankan di SQL Editor Supabase (database License Manager) jika startup tidak bisa
-- menambahkan kolom otomatis. Tidak menghapus atau mengubah data.
ALTER TABLE public.licenses          ADD COLUMN IF NOT EXISTS deleted_at timestamptz NULL;
CREATE INDEX IF NOT EXISTS ix_licenses_deleted_at ON public.licenses (deleted_at);
ALTER TABLE public.package_modules   ADD COLUMN IF NOT EXISTS is_mandatory boolean NOT NULL DEFAULT TRUE;
-- installations.customer_id sengaja nullable agar instalasi lama tetap terbaca:
ALTER TABLE public.installations     ADD COLUMN IF NOT EXISTS customer_id uuid NULL REFERENCES public.customers(id) ON DELETE CASCADE;
