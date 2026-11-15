"""Create or reset the License Manager SUPERADMIN account safely."""
import sys
from pathlib import Path
from getpass import getpass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings
from app.database.session import SessionLocal
from app.models.user import LicenseUser
from app.security.hashing import hash_password


def main():
    settings = get_settings()
    username = input(f"Username [{settings.ADMIN_USERNAME}]: ").strip() or settings.ADMIN_USERNAME
    password = getpass("Password baru: ")
    confirm = getpass("Ulangi password: ")
    if len(password) < 12:
        raise SystemExit("Password minimal 12 karakter.")
    if password != confirm:
        raise SystemExit("Konfirmasi password tidak sama.")

    db = SessionLocal()
    try:
        user = db.query(LicenseUser).filter(LicenseUser.username == username).first()
        if user is None:
            user = LicenseUser(
                username=username, email=settings.ADMIN_EMAIL,
                full_name=settings.ADMIN_FULL_NAME,
                password_hash=hash_password(password),
                role="SUPERADMIN", is_active=True
            )
            db.add(user)
            action = "dibuat"
        else:
            user.password_hash = hash_password(password)
            user.role = "SUPERADMIN"
            user.is_active = True
            action = "direset"
        db.commit()
        print(f"Akun SUPERADMIN {username} berhasil {action} pada database yang dikonfigurasi.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
