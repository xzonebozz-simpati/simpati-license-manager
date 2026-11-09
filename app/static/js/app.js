/**
 * SIMPATI LICENSE MANAGER - Interactive Client Script
 * Handles real-time actions, customer management, modals, CSRF headers, and secure API requests.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Helper to extract CSRF token from meta tag or cookie
    window.getCsrfToken = function() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta && meta.getAttribute('content')) {
            return meta.getAttribute('content');
        }
        const match = document.cookie.match(/simpati_csrf_token=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : '';
    };

    // Modal Helpers
    window.openModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('active');
        }
    };

    window.closeModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('active');
        }
    };

    // Close modal on click outside container
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.classList.remove('active');
            }
        });
    });

    // =========================================================================
    // Customer Management: Create, Detail, Edit, Status Toggle, Safe Delete
    // =========================================================================

    // 1. Form: Create Customer
    const formNewCustomer = document.getElementById('formNewCustomer');
    if (formNewCustomer) {
        formNewCustomer.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = formNewCustomer.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Menyimpan...';

            const payload = {
                customer_code: document.getElementById('custCode').value.trim(),
                organization_name: document.getElementById('custOrgName').value.trim(),
                contact_person: document.getElementById('custPerson').value.trim(),
                contact_email: document.getElementById('custEmail').value.trim(),
                contact_phone: document.getElementById('custPhone').value.trim(),
                address: document.getElementById('custAddress').value.trim(),
                notes: document.getElementById('custNotes').value.trim()
            };

            try {
                const res = await fetch('/api/v1/customers', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Pelanggan berhasil didaftarkan: ' + data.organization_name);
                    window.location.reload();
                } else if (res.status === 401) {
                    alert('Sesi Anda telah berakhir. Anda akan diarahkan ke halaman login.');
                    window.location.href = '/login';
                } else {
                    alert('Gagal mendaftarkan pelanggan: ' + (data.detail || 'Terjadi kesalahan sistem.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // 2. View Customer Detail & Relations
    window.viewCustomerDetail = async function(customerId) {
        try {
            const res = await fetch(`/api/v1/customers/${customerId}/detail`, {
                headers: { 'X-CSRF-Token': window.getCsrfToken() },
                credentials: 'same-origin'
            });
            if (!res.ok) {
                alert('Gagal memuat detail pelanggan.');
                return;
            }
            const data = await res.json();

            // Populate info
            document.getElementById('detailModalTitle').innerText = `Detail Organisasi: ${data.organization_name}`;
            document.getElementById('detailCode').innerText = data.customer_code;
            document.getElementById('detailOrg').innerText = data.organization_name;
            document.getElementById('detailPerson').innerText = data.contact_person;
            document.getElementById('detailEmail').innerText = data.contact_email;
            document.getElementById('detailPhone').innerText = data.contact_phone || '-';
            document.getElementById('detailAddress').innerText = data.address || '-';
            document.getElementById('detailCreatedAt').innerText = new Date(data.created_at).toLocaleDateString('id-ID');

            // Status badge
            const statusBadge = document.getElementById('detailStatusBadge');
            if (data.status === 'ACTIVE') {
                statusBadge.innerHTML = '<span class="badge badge-active">&bull; AKTIF</span>';
            } else if (data.status === 'SUSPENDED') {
                statusBadge.innerHTML = '<span class="badge badge-restricted">&bull; SUSPENDED</span>';
            } else {
                statusBadge.innerHTML = `<span class="badge badge-revoked">&bull; ${data.status}</span>`;
            }

            // Stats
            document.getElementById('detailTotalInst').innerText = data.total_installations;
            document.getElementById('detailTotalLic').innerText = data.total_licenses;
            document.getElementById('tabCountInst').innerText = data.total_installations;
            document.getElementById('tabCountLic').innerText = data.total_licenses;

            // Installations table
            const instTbody = document.getElementById('detailInstTbody');
            if (data.installations && data.installations.length > 0) {
                instTbody.innerHTML = data.installations.map(inst => `
                    <tr>
                        <td class="font-mono"><strong>${inst.installation_code}</strong></td>
                        <td>${inst.name}</td>
                        <td class="font-mono">${inst.server_domain || '-'}</td>
                        <td class="font-mono">${inst.server_ip || '-'}</td>
                        <td><span class="badge badge-gold">${inst.environment}</span></td>
                        <td><span class="badge ${inst.status === 'ACTIVE' ? 'badge-active' : 'badge-restricted'}">${inst.status}</span></td>
                    </tr>
                `).join('');
            } else {
                instTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 18px;">Belum ada server instalasi terdaftar untuk pelanggan ini.</td></tr>`;
            }

            // Licenses table
            const licTbody = document.getElementById('detailLicTbody');
            if (data.licenses && data.licenses.length > 0) {
                licTbody.innerHTML = data.licenses.map(lic => `
                    <tr>
                        <td class="font-mono"><strong>${lic.license_key}</strong></td>
                        <td><span class="badge badge-gold">${lic.package_name}</span></td>
                        <td>${lic.license_type}</td>
                        <td>${new Date(lic.valid_until).toLocaleDateString('id-ID')}</td>
                        <td>${lic.grace_period_days} Hari</td>
                        <td><span class="badge ${lic.status === 'ACTIVE' ? 'badge-active' : (lic.status === 'GRACE_PERIOD' ? 'badge-grace' : 'badge-restricted')}">${lic.status}</span></td>
                    </tr>
                `).join('');
            } else {
                licTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 18px;">Belum ada lisensi komersial diterbitkan untuk pelanggan ini.</td></tr>`;
            }

            window.switchCustomerDetailTab('inst');
            window.openModal('modalCustomerDetail');
        } catch (err) {
            alert('Kesalahan saat memuat detail: ' + err.message);
        }
    };

    // Tab switcher in customer detail modal
    window.switchCustomerDetailTab = function(tab) {
        const tabInst = document.getElementById('tabContentInst');
        const tabLic = document.getElementById('tabContentLic');
        const btnInst = document.getElementById('tabBtnInst');
        const btnLic = document.getElementById('tabBtnLic');

        if (tab === 'inst') {
            tabInst.style.display = 'block';
            tabLic.style.display = 'none';
            btnInst.style.background = 'var(--maroon-primary)';
            btnInst.style.borderColor = 'var(--gold-primary)';
            btnLic.style.background = 'rgba(82, 11, 24, 0.4)';
            btnLic.style.borderColor = 'var(--border-color)';
        } else {
            tabInst.style.display = 'none';
            tabLic.style.display = 'block';
            btnLic.style.background = 'var(--maroon-primary)';
            btnLic.style.borderColor = 'var(--gold-primary)';
            btnInst.style.background = 'rgba(82, 11, 24, 0.4)';
            btnInst.style.borderColor = 'var(--border-color)';
        }
    };

    // 3. Open Edit Customer Modal
    window.openEditCustomer = function(id, code, orgName, person, email, phone, address, notes) {
        document.getElementById('editCustId').value = id;
        document.getElementById('editCustCode').value = code;
        document.getElementById('editCustOrgName').value = orgName;
        document.getElementById('editCustPerson').value = person;
        document.getElementById('editCustEmail').value = email;
        document.getElementById('editCustPhone').value = phone || '';
        document.getElementById('editCustAddress').value = address || '';
        document.getElementById('editCustNotes').value = notes || '';
        window.openModal('modalEditCustomer');
    };

    // Form: Edit Customer Submit
    const formEditCustomer = document.getElementById('formEditCustomer');
    if (formEditCustomer) {
        formEditCustomer.addEventListener('submit', async (e) => {
            e.preventDefault();
            const customerId = document.getElementById('editCustId').value;
            const submitBtn = formEditCustomer.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Menyimpan...';

            const payload = {
                organization_name: document.getElementById('editCustOrgName').value.trim(),
                contact_person: document.getElementById('editCustPerson').value.trim(),
                contact_email: document.getElementById('editCustEmail').value.trim(),
                contact_phone: document.getElementById('editCustPhone').value.trim(),
                address: document.getElementById('editCustAddress').value.trim(),
                notes: document.getElementById('editCustNotes').value.trim()
            };

            try {
                const res = await fetch(`/api/v1/customers/${customerId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Data pelanggan berhasil diperbarui!');
                    window.location.reload();
                } else if (res.status === 401) {
                    alert('Sesi Anda telah berakhir. Anda akan diarahkan ke login.');
                    window.location.href = '/login';
                } else {
                    alert('Gagal memperbarui data: ' + (data.detail || 'Terjadi kesalahan sistem.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // 4. Toggle Customer Status (ACTIVE <-> SUSPENDED)
    window.toggleCustomerStatus = async function(customerId, newStatus) {
        const actionLabel = newStatus === 'ACTIVE' ? 'mengaktifkan kembali' : 'menonaktifkan (suspend)';
        if (!confirm(`Apakah Anda yakin ingin ${actionLabel} pelanggan ini?`)) {
            return;
        }

        try {
            const res = await fetch(`/api/v1/customers/${customerId}/status`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.getCsrfToken()
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    status: newStatus,
                    reason: `Pengubahan status manual menjadi ${newStatus}`
                })
            });
            const data = await res.json();
            if (res.ok) {
                alert(`Status pelanggan berhasil diubah menjadi: ${data.status}`);
                window.location.reload();
            } else if (res.status === 401) {
                window.location.href = '/login';
            } else {
                alert('Gagal mengubah status: ' + (data.detail || 'Terjadi kesalahan sistem.'));
            }
        } catch (err) {
            alert('Kesalahan jaringan: ' + err.message);
        }
    };

    // 5. Delete Customer with Relational Checks
    let pendingDeleteCustomerId = null;

    window.confirmDeleteCustomer = function(customerId, orgName) {
        pendingDeleteCustomerId = customerId;
        document.getElementById('deleteTargetOrgName').innerText = orgName;
        window.openModal('modalDeleteCustomerConfirm');
    };

    const btnExecuteDelete = document.getElementById('btnExecuteDeleteCustomer');
    if (btnExecuteDelete) {
        btnExecuteDelete.addEventListener('click', async () => {
            if (!pendingDeleteCustomerId) return;

            btnExecuteDelete.disabled = true;
            btnExecuteDelete.innerText = 'Memeriksa & Menghapus...';

            try {
                const res = await fetch(`/api/v1/customers/${pendingDeleteCustomerId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin'
                });
                const data = await res.json();
                window.closeModal('modalDeleteCustomerConfirm');

                if (res.ok) {
                    alert(data.message || 'Pelanggan berhasil dihapus.');
                    window.location.reload();
                } else if (res.status === 400) {
                    // Relational guard rejection
                    alert('PENOLAKAN PENGHAPUSAN:\n' + data.detail);
                } else if (res.status === 401) {
                    window.location.href = '/login';
                } else {
                    alert('Gagal menghapus: ' + (data.detail || 'Terjadi kesalahan server.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                btnExecuteDelete.disabled = false;
                btnExecuteDelete.innerText = 'Ya, Hapus Pelanggan';
                pendingDeleteCustomerId = null;
            }
        });
    }

    // =========================================================================
    // Package Management (Iterasi 5)
    // =========================================================================

    // 1. Form Tambah Paket
    const formNewPackage = document.getElementById('formNewPackage');
    if (formNewPackage) {
        formNewPackage.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = formNewPackage.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Menyimpan...';

            const selectedModules = [];
            document.querySelectorAll('input[name="pkg_modules"]:checked').forEach(cb => selectedModules.push(cb.value));

            const selectedLevels = [];
            document.querySelectorAll('input[name="pkg_levels"]:checked').forEach(cb => selectedLevels.push(cb.value));

            const payload = {
                package_code: document.getElementById('newPkgCode').value.trim().toUpperCase(),
                package_name: document.getElementById('newPkgName').value.trim(),
                default_tier: document.getElementById('newPkgTier').value,
                billing_period: document.getElementById('newPkgPeriod').value,
                default_max_members: parseInt(document.getElementById('newPkgMaxMembers').value, 10) || 50000,
                description: document.getElementById('newPkgDesc').value.trim(),
                modules: selectedModules.length > 0 ? selectedModules : ['CORE'],
                levels: selectedLevels.length > 0 ? selectedLevels : ['DPD', 'DPC']
            };

            try {
                const res = await fetch('/api/v1/packages', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Paket komersial berhasil dibuat: ' + data.package_name);
                    window.location.reload();
                } else {
                    alert('Gagal membuat paket: ' + (data.detail || 'Periksa input form.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // 2. Open Edit Package
    window.openEditPackage = async function(packageId) {
        try {
            const res = await fetch(`/api/v1/packages/${packageId}/detail`, {
                headers: { 'X-CSRF-Token': window.getCsrfToken() },
                credentials: 'same-origin'
            });
            if (!res.ok) {
                alert('Gagal mengambil data paket.');
                return;
            }
            const data = await res.json();

            document.getElementById('editPkgId').value = data.id;
            document.getElementById('editPkgCode').value = data.package_code;
            document.getElementById('editPkgName').value = data.package_name;
            document.getElementById('editPkgTier').value = data.default_tier;
            document.getElementById('editPkgPeriod').value = data.billing_period || 'TAHUNAN';
            document.getElementById('editPkgMaxMembers').value = data.default_max_members || 50000;
            document.getElementById('editPkgDesc').value = data.description || '';

            // Check modules
            document.querySelectorAll('input[name="edit_pkg_modules"]').forEach(cb => {
                cb.checked = data.modules && data.modules.includes(cb.value);
            });

            // Check levels
            document.querySelectorAll('input[name="edit_pkg_levels"]').forEach(cb => {
                cb.checked = data.default_levels && data.default_levels.includes(cb.value);
            });

            openModal('modalEditPackage');
        } catch (err) {
            alert('Kesalahan jaringan: ' + err.message);
        }
    };

    const formEditPackage = document.getElementById('formEditPackage');
    if (formEditPackage) {
        formEditPackage.addEventListener('submit', async (e) => {
            e.preventDefault();
            const pkgId = document.getElementById('editPkgId').value;
            const submitBtn = formEditPackage.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Menyimpan...';

            const selectedModules = [];
            document.querySelectorAll('input[name="edit_pkg_modules"]:checked').forEach(cb => selectedModules.push(cb.value));

            const selectedLevels = [];
            document.querySelectorAll('input[name="edit_pkg_levels"]:checked').forEach(cb => selectedLevels.push(cb.value));

            const payload = {
                package_name: document.getElementById('editPkgName').value.trim(),
                default_tier: document.getElementById('editPkgTier').value,
                billing_period: document.getElementById('editPkgPeriod').value,
                default_max_members: parseInt(document.getElementById('editPkgMaxMembers').value, 10) || 50000,
                description: document.getElementById('editPkgDesc').value.trim(),
                modules: selectedModules,
                levels: selectedLevels
            };

            try {
                const res = await fetch(`/api/v1/packages/${pkgId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Paket komersial berhasil diperbarui: ' + data.package_name);
                    window.location.reload();
                } else {
                    alert('Gagal memperbarui paket: ' + (data.detail || 'Periksa isian form.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // 3. View Package Detail
    window.viewPackageDetail = async function(packageId) {
        try {
            const res = await fetch(`/api/v1/packages/${packageId}/detail`, {
                headers: { 'X-CSRF-Token': window.getCsrfToken() },
                credentials: 'same-origin'
            });
            if (!res.ok) {
                alert('Gagal mengambil detail paket.');
                return;
            }
            const data = await res.json();

            document.getElementById('detPkgName').innerText = data.package_name;
            document.getElementById('detPkgCode').innerText = data.package_code;
            document.getElementById('detPkgTierBadge').innerText = data.default_tier;
            document.getElementById('detPkgStatusBadge').innerText = data.is_active ? '• AKTIF' : '• NON-AKTIF';
            document.getElementById('detPkgStatusBadge').className = 'badge ' + (data.is_active ? 'badge-active' : 'badge-revoked');
            document.getElementById('detPkgPeriod').innerText = data.billing_period || 'TAHUNAN';
            document.getElementById('detPkgMaxMembers').innerText = (data.default_max_members || 50000).toLocaleString('id-ID') + ' Anggota';
            document.getElementById('detPkgTotalLic').innerText = data.total_licenses + ' Lisensi';
            document.getElementById('detPkgCreatedAt').innerText = new Date(data.created_at).toLocaleDateString('id-ID');
            document.getElementById('detPkgDesc').innerText = data.description || 'Tidak ada deskripsi khusus.';

            const modContainer = document.getElementById('detPkgModulesList');
            modContainer.innerHTML = '';
            if (data.modules && data.modules.length > 0) {
                data.modules.forEach(m => {
                    const span = document.createElement('span');
                    span.className = 'badge badge-gold';
                    span.innerText = m;
                    modContainer.appendChild(span);
                });
            } else {
                modContainer.innerHTML = '<span style="color: var(--text-muted);">Tidak ada modul.</span>';
            }

            const lvlContainer = document.getElementById('detPkgLevelsList');
            lvlContainer.innerHTML = '';
            if (data.default_levels && data.default_levels.length > 0) {
                data.default_levels.forEach(lvl => {
                    const span = document.createElement('span');
                    span.className = 'badge badge-secondary';
                    span.innerText = lvl;
                    lvlContainer.appendChild(span);
                });
            }

            openModal('modalPackageDetail');
        } catch (err) {
            alert('Kesalahan jaringan: ' + err.message);
        }
    };

    // 4. Toggle Package Status
    window.togglePackageStatus = async function(packageId, newStatus) {
        const action = newStatus ? 'mengaktifkan' : 'menonaktifkan';
        if (!confirm(`Apakah Anda yakin ingin ${action} paket lisensi ini?`)) return;

        try {
            const res = await fetch(`/api/v1/packages/${packageId}/status`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.getCsrfToken()
                },
                credentials: 'same-origin',
                body: JSON.stringify({ is_active: newStatus })
            });
            if (res.ok) {
                window.location.reload();
            } else {
                const data = await res.json();
                alert('Gagal mengubah status paket: ' + (data.detail || 'Terjadi kesalahan'));
            }
        } catch (err) {
            alert('Kesalahan jaringan: ' + err.message);
        }
    };

    // =========================================================================
    // Commercial License Management (Iterasi 5)
    // =========================================================================

    // Dynamic Filter Installation based on Customer
    window.onLicenseCustomerChange = function(customerId) {
        const instSelect = document.getElementById('licInstallationId');
        if (!instSelect) return;
        const options = instSelect.querySelectorAll('option');
        let matchCount = 0;

        options.forEach(opt => {
            const custAttr = opt.getAttribute('data-customer-id');
            if (!custAttr) {
                opt.style.display = 'block'; // placeholder
            } else if (!customerId || custAttr === customerId) {
                opt.style.display = 'block';
                matchCount++;
            } else {
                opt.style.display = 'none';
            }
        });

        // Reset to first option
        instSelect.value = '';
    };

    // Dynamic Module & Capacity Preset based on Package
    window.onLicensePackageChange = async function(packageId) {
        if (!packageId) return;
        try {
            const res = await fetch(`/api/v1/packages/${packageId}/detail`, {
                headers: { 'X-CSRF-Token': window.getCsrfToken() },
                credentials: 'same-origin'
            });
            if (!res.ok) return;
            const data = await res.json();

            // Check default modules of this package
            if (data.modules) {
                document.querySelectorAll('#licModulesContainer input[name="modules"]').forEach(cb => {
                    if (cb.value === 'CORE') {
                        cb.checked = true;
                    } else {
                        cb.checked = data.modules.includes(cb.value);
                    }
                });
            }

            // Set capacity default
            if (data.default_max_members) {
                const capEl = document.getElementById('capMembers');
                if (capEl) capEl.value = data.default_max_members;
            }

            // Set levels default
            if (data.default_levels) {
                document.querySelectorAll('input[name="levels"]').forEach(cb => {
                    cb.checked = data.default_levels.includes(cb.value);
                });
            }
        } catch (e) {
            // silent fallback
        }
    };

    // Form: Issue License
    const formNewLicense = document.getElementById('formNewLicense');
    if (formNewLicense) {
        // Set default dates if empty
        const fromEl = document.getElementById('licValidFrom');
        const untilEl = document.getElementById('licValidUntil');
        if (fromEl && !fromEl.value) {
            const today = new Date();
            fromEl.value = today.toISOString().split('T')[0];
            const nextYear = new Date(today);
            nextYear.setFullYear(today.getFullYear() + 1);
            if (untilEl) untilEl.value = nextYear.toISOString().split('T')[0];
        }

        formNewLicense.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = formNewLicense.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Menerbitkan & Menandatangani...';

            const selectedModules = [];
            document.querySelectorAll('input[name="modules"]:checked').forEach(cb => {
                selectedModules.push(cb.value);
            });

            const selectedLevels = [];
            document.querySelectorAll('input[name="levels"]:checked').forEach(cb => {
                selectedLevels.push(cb.value);
            });

            const validFromStr = document.getElementById('licValidFrom').value;
            const validUntilStr = document.getElementById('licValidUntil').value;
            const instIdVal = document.getElementById('licInstallationId').value;

            const payload = {
                customer_id: document.getElementById('licCustomerId').value,
                package_id: document.getElementById('licPackageId').value,
                installation_id: instIdVal || null,
                license_type: document.getElementById('licType').value,
                valid_from: new Date(validFromStr + 'T00:00:00Z').toISOString(),
                valid_until: new Date(validUntilStr + 'T23:59:59Z').toISOString(),
                grace_period_days: parseInt(document.getElementById('licGraceDays').value, 10),
                max_installations: parseInt(document.getElementById('licMaxInst').value, 10),
                modules: selectedModules.length > 0 ? selectedModules : ['CORE', 'DATA'],
                levels: selectedLevels.length > 0 ? selectedLevels : ['DPD', 'DPC'],
                capacity: {
                    max_members: parseInt(document.getElementById('capMembers').value, 10),
                    max_accounts: parseInt(document.getElementById('capAccounts').value, 10),
                    max_concurrent_users: parseInt(document.getElementById('capConcurrent').value, 10),
                    max_storage_mb: parseInt(document.getElementById('capStorage').value, 10),
                    max_gps_points_per_month: 100000
                },
                notes: document.getElementById('licNotes').value.trim() || null
            };

            try {
                const res = await fetch('/api/v1/licenses', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Lisensi komersial berhasil diterbitkan dan ditandatangani kriptografis!\nKunci: ' + data.license_key);
                    window.location.reload();
                } else if (res.status === 401) {
                    alert('Sesi Anda telah berakhir. Anda akan diarahkan ke login.');
                    window.location.href = '/login';
                } else {
                    alert('Gagal menerbitkan lisensi: ' + (data.detail || 'Periksa input form.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // Tab switcher for License Detail Modal
    window.switchLicTab = function(tabId) {
        document.querySelectorAll('#modalLicenseDetail .tab-pane').forEach(p => p.style.display = 'none');
        document.querySelectorAll('#modalLicenseDetail .tab-btn').forEach(b => b.classList.remove('active'));

        const target = document.getElementById(tabId);
        if (target) target.style.display = 'block';

        const btn = Array.from(document.querySelectorAll('#modalLicenseDetail .tab-btn')).find(b =>
            b.getAttribute('onclick') && b.getAttribute('onclick').includes(tabId)
        );
        if (btn) btn.classList.add('active');
    };

    // View License Detail
    window.viewLicenseDetail = async function(licenseId) {
        try {
            const res = await fetch(`/api/v1/licenses/${licenseId}/detail`, {
                headers: { 'X-CSRF-Token': window.getCsrfToken() },
                credentials: 'same-origin'
            });
            if (!res.ok) {
                alert('Gagal memuat detail lisensi.');
                return;
            }
            const data = await res.json();

            document.getElementById('detLicKey').innerText = data.license_key;
            document.getElementById('detLicCustName').innerText = `${data.customer_name} (${data.customer_code})`;
            document.getElementById('detLicPkgName').innerText = data.package_name;

            // Badges
            const statusEl = document.getElementById('detLicStatusBadge');
            const comp = data.computed_status;
            statusEl.innerText = '• ' + comp;
            statusEl.className = 'badge ' + (comp === 'ACTIVE' ? 'badge-active' : (comp === 'GRACE_PERIOD' ? 'badge-grace' : (comp === 'RESTRICTED' ? 'badge-restricted' : 'badge-revoked')));

            const sigBadge = document.getElementById('detLicSignatureBadge');
            if (data.signature_valid) {
                sigBadge.innerText = '🔒 Ed25519 Terverifikasi';
                sigBadge.className = 'badge badge-active';
            } else {
                sigBadge.innerText = '⚠️ Signature Tidak Valid';
                sigBadge.className = 'badge badge-revoked';
            }

            // Overview Tab
            document.getElementById('detLicFrom').innerText = new Date(data.valid_from).toLocaleDateString('id-ID');
            document.getElementById('detLicUntil').innerText = new Date(data.valid_until).toLocaleDateString('id-ID');
            document.getElementById('detLicGrace').innerText = data.grace_period_days + ' Hari';
            document.getElementById('detLicMaxInst').innerText = data.max_installations + ' Server';
            document.getElementById('detLicType').innerText = data.license_type;
            document.getElementById('detLicNotes').innerText = data.notes || '-';

            // Installations table
            const instBody = document.getElementById('detLicInstallationsBody');
            instBody.innerHTML = '';
            if (data.installations && data.installations.length > 0) {
                data.installations.forEach(inst => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="font-mono"><strong>${inst.installation_code}</strong></td>
                        <td>${inst.name}</td>
                        <td><span class="badge badge-secondary">${inst.environment}</span></td>
                        <td><span class="badge ${inst.status === 'ACTIVE' ? 'badge-active' : 'badge-revoked'}">${inst.status}</span></td>
                    `;
                    instBody.appendChild(tr);
                });
            } else {
                instBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Belum ada server instalasi yang dihubungkan ke lisensi ini.</td></tr>';
            }

            // Modules Tab
            const modContainer = document.getElementById('detLicModulesList');
            modContainer.innerHTML = '';
            if (data.modules && data.modules.length > 0) {
                data.modules.forEach(m => {
                    const span = document.createElement('span');
                    span.className = 'badge badge-gold';
                    span.innerText = m;
                    modContainer.appendChild(span);
                });
            }

            const lvlContainer = document.getElementById('detLicLevelsList');
            lvlContainer.innerHTML = '';
            if (data.levels && data.levels.length > 0) {
                data.levels.forEach(lvl => {
                    const span = document.createElement('span');
                    span.className = 'badge badge-secondary';
                    span.innerText = lvl;
                    lvlContainer.appendChild(span);
                });
            }

            // Capacity
            if (data.capacity) {
                document.getElementById('detCapMembers').innerText = (data.capacity.max_members || 0).toLocaleString('id-ID');
                document.getElementById('detCapAccounts').innerText = (data.capacity.max_accounts || 0).toLocaleString('id-ID');
                document.getElementById('detCapConcurrent').innerText = (data.capacity.max_concurrent_users || 0).toLocaleString('id-ID');
                document.getElementById('detCapStorage').innerText = (data.capacity.max_storage_mb || 0) + ' MB';
            }

            // Crypto Tab
            document.getElementById('detLicSignatureText').value = data.signature || 'Belum ada tanda tangan';
            document.getElementById('detLicSnapshotText').value = data.snapshot_entitlements || '{}';

            // History Tab
            document.getElementById('detLicHistoryCount').innerText = data.history ? data.history.length : 0;
            const histBody = document.getElementById('detLicHistoryBody');
            histBody.innerHTML = '';
            if (data.history && data.history.length > 0) {
                data.history.forEach(h => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${new Date(h.created_at).toLocaleString('id-ID')}</td>
                        <td><span class="badge badge-secondary">${h.action}</span></td>
                        <td>${h.performed_by_name || 'Superadmin'}</td>
                        <td>${h.remarks || '-'}</td>
                    `;
                    histBody.appendChild(tr);
                });
            } else {
                histBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Belum ada riwayat aktivitas.</td></tr>';
            }

            window.switchLicTab('tab-lic-overview');
            openModal('modalLicenseDetail');
        } catch (err) {
            alert('Kesalahan saat memuat detail lisensi: ' + err.message);
        }
    };

    // Open Extend License Modal
    window.openExtendLicenseModal = function(licenseId, licenseKey, currentUntilDate) {
        document.getElementById('extLicId').value = licenseId;
        document.getElementById('extLicKey').value = licenseKey;
        document.getElementById('extLicCurrentUntil').value = currentUntilDate;

        // Set suggested new expiration date (+1 year from current)
        const curDate = new Date(currentUntilDate);
        curDate.setFullYear(curDate.getFullYear() + 1);
        document.getElementById('extLicNewUntil').value = curDate.toISOString().split('T')[0];
        document.getElementById('extLicReason').value = '';

        openModal('modalExtendLicense');
    };

    const formExtendLicense = document.getElementById('formExtendLicense');
    if (formExtendLicense) {
        formExtendLicense.addEventListener('submit', async (e) => {
            e.preventDefault();
            const licId = document.getElementById('extLicId').value;
            const submitBtn = formExtendLicense.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Memperpanjang...';

            const payload = {
                valid_until: new Date(document.getElementById('extLicNewUntil').value + 'T23:59:59Z').toISOString(),
                reason: document.getElementById('extLicReason').value.trim()
            };

            try {
                const res = await fetch(`/api/v1/licenses/${licId}/extend`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Lisensi berhasil diperpanjang!');
                    window.location.reload();
                } else {
                    alert('Gagal memperpanjang lisensi: ' + (data.detail || 'Terjadi kesalahan.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // Open License Status Modal
    window.openLicenseStatusModal = function(licenseId, licenseKey, currentStatus) {
        document.getElementById('statusLicId').value = licenseId;
        document.getElementById('statusLicKey').value = licenseKey;
        document.getElementById('statusLicTarget').value = currentStatus === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE';
        document.getElementById('statusLicReason').value = '';
        openModal('modalLicenseStatus');
    };

    const formLicenseStatus = document.getElementById('formLicenseStatus');
    if (formLicenseStatus) {
        formLicenseStatus.addEventListener('submit', async (e) => {
            e.preventDefault();
            const licId = document.getElementById('statusLicId').value;
            const targetStatus = document.getElementById('statusLicTarget').value;
            const reason = document.getElementById('statusLicReason').value.trim();

            if (targetStatus === 'REVOKED') {
                if (!confirm('PERINGATAN KERAS:\nPencabutan (REVOKE) lisensi akan memasukkan lisensi ke daftar pencabutan (CRL). Klien SIMPATI akan otomatis masuk ke RESTRICTED MODE permanen!\n\nLanjutkan?')) {
                    return;
                }
            }

            const submitBtn = formLicenseStatus.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Menerapkan...';

            try {
                const res = await fetch(`/api/v1/licenses/${licId}/status`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ status: targetStatus, reason: reason })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Status lisensi berhasil diperbarui!');
                    window.location.reload();
                } else {
                    alert('Gagal mengubah status: ' + (data.detail || 'Terjadi kesalahan.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // Quick Test Validation Trigger
    window.testValidation = async function(licenseKey, installationCode) {
        try {
            const res = await fetch('/api/v1/validations/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.getCsrfToken()
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    license_key: licenseKey,
                    installation_code: installationCode,
                    nonce: 'test-nonce-' + Date.now(),
                    timestamp: new Date().toISOString()
                })
            });
            const data = await res.json();
            alert(`Hasil Validasi Online:\nStatus: ${data.validation_status}\nRestricted Mode: ${data.is_restricted_mode ? 'AKTIF' : 'NON-AKTIF'}\nToken: ${data.validation_token}\nJatuh Tempo Berikutnya: ${data.next_validation_due}`);
        } catch (err) {
            alert('Gagal menghubungi endpoint validasi: ' + err.message);
        }
    };

    // =========================================================================
    // Utility: Copy to Clipboard
    // =========================================================================
    window.copyToClipboard = function(elementId) {
        const el = document.getElementById(elementId);
        if (!el) return;
        const text = el.value || el.innerText;
        navigator.clipboard.writeText(text).then(() => {
            alert('Berhasil disalin ke clipboard!');
        }).catch(() => {
            el.select();
            document.execCommand('copy');
            alert('Berhasil disalin ke clipboard!');
        });
    };

    // =========================================================================
    // Module: Installation Management (Iterasi 4)
    // =========================================================================

    // 1. Form Pendaftaran Instalasi Baru
    const formNewInstallation = document.getElementById('formNewInstallation');
    if (formNewInstallation) {
        formNewInstallation.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = formNewInstallation.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Mendaftarkan...';

            const payload = {
                customer_id: document.getElementById('instCustomerId').value,
                name: document.getElementById('instName').value.trim(),
                installation_code: document.getElementById('instCode').value.trim() || null,
                environment: document.getElementById('instEnvironment').value,
                server_domain: document.getElementById('instDomain').value.trim() || null,
                server_ip: document.getElementById('instIp').value.trim() || null,
                hardware_signature: document.getElementById('instHardwareSig').value.trim() || null,
                public_key_pem: document.getElementById('instPublicKeyPem').value.trim() || null
            };

            try {
                const res = await fetch('/api/v1/installations', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    closeModal('modalNewInstallation');
                    // Tampilkan modal kredensial baru (one-time view)
                    document.getElementById('successInstCode').value = data.installation_code;
                    document.getElementById('successClientId').value = data.client_id;
                    document.getElementById('successClientSecret').value = data.client_secret;

                    const envSnippet = 
                        `# SIMPATI 555 - LICENSE INTEGRATION CONFIG\n` +
                        `SIMPATI_LICENSE_SERVER_URL=${window.location.origin}\n` +
                        `SIMPATI_INSTALLATION_CODE=${data.installation_code}\n` +
                        `SIMPATI_CLIENT_ID=${data.client_id}\n` +
                        `SIMPATI_CLIENT_SECRET=${data.client_secret}\n` +
                        `SIMPATI_ENVIRONMENT=${data.environment}\n`;
                    document.getElementById('successEnvSnippet').value = envSnippet;

                    openModal('modalCredentialsSuccess');
                } else if (res.status === 401) {
                    alert('Sesi Anda telah berakhir. Anda akan diarahkan ke login.');
                    window.location.href = '/login';
                } else {
                    alert('Gagal mendaftarkan instalasi: ' + (data.detail || 'Periksa isian form.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // 2. Tab switcher di Modal Detail Instalasi
    window.switchInstTab = function(tabId) {
        document.querySelectorAll('#modalInstallationDetail .tab-pane').forEach(p => p.style.display = 'none');
        document.querySelectorAll('#modalInstallationDetail .tab-btn').forEach(b => b.classList.remove('active'));

        const targetPane = document.getElementById(tabId);
        if (targetPane) targetPane.style.display = 'block';

        const activeBtn = Array.from(document.querySelectorAll('#modalInstallationDetail .tab-btn')).find(b => 
            b.getAttribute('onclick') && b.getAttribute('onclick').includes(tabId)
        );
        if (activeBtn) activeBtn.classList.add('active');
    };

    // 3. View Installation Detail
    window.viewInstallationDetail = async function(installationId) {
        try {
            const res = await fetch(`/api/v1/installations/${installationId}/detail`, {
                headers: { 'X-CSRF-Token': window.getCsrfToken() },
                credentials: 'same-origin'
            });
            if (!res.ok) {
                alert('Gagal memuat detail instalasi.');
                return;
            }
            const data = await res.json();

            document.getElementById('detInstName').innerText = data.name;
            document.getElementById('detInstCode').innerText = data.installation_code;
            document.getElementById('detCustName').innerText = data.customer_name || 'Organisasi Pelanggan';

            // Badges
            const statusEl = document.getElementById('detInstStatusBadge');
            statusEl.innerText = data.status === 'ACTIVE' ? '• AKTIF' : (data.status === 'SUSPENDED' ? '• SUSPENDED' : '• ' + data.status);
            statusEl.className = 'badge ' + (data.status === 'ACTIVE' ? 'badge-active' : (data.status === 'SUSPENDED' ? 'badge-restricted' : 'badge-revoked'));

            const envEl = document.getElementById('detInstEnvBadge');
            envEl.innerText = data.environment;

            // Overview Tab
            document.getElementById('detDomain').innerText = data.server_domain || '-';
            document.getElementById('detIp').innerText = data.server_ip || '-';
            document.getElementById('detHeartbeat').innerText = data.last_heartbeat_at ? new Date(data.last_heartbeat_at).toLocaleString('id-ID') : 'Belum ada ping';
            document.getElementById('detHardwareSig').innerText = data.hardware_signature || 'Tidak diatur';
            document.getElementById('detCreatedAt').innerText = new Date(data.created_at).toLocaleDateString('id-ID');
            document.getElementById('detLicenseCount').innerText = data.total_license_links;

            // Public Key PEM & Fingerprint
            const fpBadge = document.getElementById('detKeyFingerprintBadge');
            const pemPre = document.getElementById('detPublicKeyPem');
            if (data.public_key_pem) {
                fpBadge.innerText = 'Fingerprint: ' + (data.public_key_fingerprint || 'VALID');
                fpBadge.className = 'badge badge-active font-mono';
                pemPre.innerText = data.public_key_pem;
            } else {
                fpBadge.innerText = 'Belum Ada';
                fpBadge.className = 'badge badge-secondary font-mono';
                pemPre.innerText = 'Belum ada public key terdaftar untuk server ini. Daftarkan kunci publik melalui tombol [Kunci].';
            }

            // Tab 2: Credentials
            document.getElementById('detCredCount').innerText = data.credentials ? data.credentials.length : 0;
            const credsBody = document.getElementById('detCredentialsTableBody');
            credsBody.innerHTML = '';
            if (data.credentials && data.credentials.length > 0) {
                data.credentials.forEach(cred => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="font-mono"><strong>${cred.client_id}</strong></td>
                        <td>${cred.is_active ? '<span class="badge badge-active">AKTIF</span>' : '<span class="badge badge-revoked">REVOKED</span>'}</td>
                        <td>${new Date(cred.created_at).toLocaleString('id-ID')}</td>
                        <td>${cred.revoked_at ? new Date(cred.revoked_at).toLocaleString('id-ID') : '-'}</td>
                    `;
                    credsBody.appendChild(tr);
                });
            } else {
                credsBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Tidak ada riwayat kredensial.</td></tr>';
            }

            // Button Rotate Credentials
            const btnRotate = document.getElementById('btnRotateCreds');
            btnRotate.onclick = () => window.rotateInstallationCredentials(data.id, data.name);

            // Tab 3: Events
            document.getElementById('detEventCount').innerText = data.events ? data.events.length : 0;
            const eventsBody = document.getElementById('detEventsTableBody');
            eventsBody.innerHTML = '';
            if (data.events && data.events.length > 0) {
                data.events.forEach(ev => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${new Date(ev.recorded_at).toLocaleString('id-ID')}</td>
                        <td><span class="badge badge-secondary">${ev.event_type}</span></td>
                        <td class="font-mono">${ev.ip_address || '-'}</td>
                        <td>${ev.payload || '-'}</td>
                    `;
                    eventsBody.appendChild(tr);
                });
            } else {
                eventsBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Belum ada riwayat aktivitas.</td></tr>';
            }

            // Tab 4: Integration
            const envConfig = 
                `# SIMPATI 555 - INTEGRASI LICENSE MANAGER PUSAT\n` +
                `SIMPATI_LICENSE_SERVER_URL=${window.location.origin}\n` +
                `SIMPATI_INSTALLATION_CODE=${data.installation_code}\n` +
                `# Gunakan Client ID yang aktif:\n` +
                `SIMPATI_CLIENT_ID=${data.credentials && data.credentials.length ? data.credentials[0].client_id : 'CLT-xxx'}\n` +
                `# Client Secret diperoleh saat pembuatan atau rotasi kredensial\n` +
                `SIMPATI_CLIENT_SECRET=<masukkan_client_secret>\n` +
                `SIMPATI_ENVIRONMENT=${data.environment}\n`;
            document.getElementById('detIntegrationEnv').value = envConfig;

            // Reset to Tab 1
            window.switchInstTab('tab-inst-overview');
            openModal('modalInstallationDetail');
        } catch (err) {
            alert('Kesalahan saat memuat detail: ' + err.message);
        }
    };

    // 4. Rotasi Kredensial API
    window.rotateInstallationCredentials = async function(installationId, instName) {
        if (!confirm(`Apakah Anda yakin ingin merotasi kredensial API untuk '${instName}'?\n\nKredensial lama akan langsung dinonaktifkan (revoked), dan server SIMPATI harus segera memperbarui konfigurasi secret barunya.`)) {
            return;
        }

        try {
            const res = await fetch(`/api/v1/installations/${installationId}/rotate-credentials`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.getCsrfToken()
                },
                credentials: 'same-origin'
            });
            const data = await res.json();
            if (res.ok) {
                closeModal('modalInstallationDetail');
                document.getElementById('successInstCode').value = instName;
                document.getElementById('successClientId').value = data.client_id;
                document.getElementById('successClientSecret').value = data.client_secret;

                const envSnippet = 
                    `# KREDENSIAL ROTASI BARU - SIMPATI 555\n` +
                    `SIMPATI_LICENSE_SERVER_URL=${window.location.origin}\n` +
                    `SIMPATI_CLIENT_ID=${data.client_id}\n` +
                    `SIMPATI_CLIENT_SECRET=${data.client_secret}\n`;
                document.getElementById('successEnvSnippet').value = envSnippet;

                openModal('modalCredentialsSuccess');
            } else {
                alert('Gagal merotasi kredensial: ' + (data.detail || 'Terjadi kesalahan'));
            }
        } catch (err) {
            alert('Kesalahan jaringan: ' + err.message);
        }
    };

    // 5. Open Edit Installation
    window.openEditInstallation = function(id, name, domain, ip, env, hardwareSig) {
        document.getElementById('editInstId').value = id;
        document.getElementById('editInstName').value = name;
        document.getElementById('editInstDomain').value = domain || '';
        document.getElementById('editInstIp').value = ip || '';
        document.getElementById('editInstEnvironment').value = env || 'PRODUCTION';
        document.getElementById('editInstHardwareSig').value = hardwareSig || '';
        openModal('modalEditInstallation');
    };

    const formEditInstallation = document.getElementById('formEditInstallation');
    if (formEditInstallation) {
        formEditInstallation.addEventListener('submit', async (e) => {
            e.preventDefault();
            const instId = document.getElementById('editInstId').value;
            const submitBtn = formEditInstallation.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Menyimpan...';

            const payload = {
                name: document.getElementById('editInstName').value.trim(),
                server_domain: document.getElementById('editInstDomain').value.trim() || null,
                server_ip: document.getElementById('editInstIp').value.trim() || null,
                environment: document.getElementById('editInstEnvironment').value,
                hardware_signature: document.getElementById('editInstHardwareSig').value.trim() || null
            };

            try {
                const res = await fetch(`/api/v1/installations/${instId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Data instalasi berhasil diperbarui: ' + data.name);
                    window.location.reload();
                } else {
                    alert('Gagal memperbarui instalasi: ' + (data.detail || 'Periksa input form.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // 6. Public Key Modal & Registration
    window.openPublicKeyModal = function(id, code) {
        document.getElementById('pubKeyInstId').value = id;
        document.getElementById('pubKeyPemText').value = '';
        openModal('modalPublicKey');
    };

    const formPublicKey = document.getElementById('formPublicKey');
    if (formPublicKey) {
        formPublicKey.addEventListener('submit', async (e) => {
            e.preventDefault();
            const instId = document.getElementById('pubKeyInstId').value;
            const pemText = document.getElementById('pubKeyPemText').value.trim();

            if (!pemText.startsWith('-----BEGIN') || !pemText.includes('-----END')) {
                alert('Format public key tidak valid. Harus diawali dengan -----BEGIN... dan diakhiri dengan -----END...');
                return;
            }

            const submitBtn = formPublicKey.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerText;
            submitBtn.disabled = true;
            submitBtn.innerText = 'Mendaftarkan...';

            try {
                const res = await fetch(`/api/v1/installations/${instId}/public-key`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ public_key_pem: pemText })
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Public key Ed25519 berhasil didaftarkan untuk instalasi!');
                    window.location.reload();
                } else {
                    alert('Gagal mendaftarkan kunci publik: ' + (data.detail || 'Format kunci tidak didukung.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerText = originalText;
            }
        });
    }

    // 7. Toggle Status (Active / Suspended / Revoked)
    window.toggleInstallationStatus = async function(instId, newStatus) {
        const actionLabel = newStatus === 'ACTIVE' ? 'mengaktifkan kembali' : 'menonaktifkan (suspend)';
        const reason = prompt(`Masukkan alasan ${actionLabel} server instalasi ini:`, newStatus === 'ACTIVE' ? 'Aktivasi operasional' : 'Maintenance server');
        if (reason === null) return; // User cancel

        try {
            const res = await fetch(`/api/v1/installations/${instId}/status`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.getCsrfToken()
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    status: newStatus,
                    reason: reason.trim() || 'Perubahan status manual oleh admin'
                })
            });
            const data = await res.json();
            if (res.ok) {
                alert(`Status server instalasi berhasil diubah menjadi: ${data.status}`);
                window.location.reload();
            } else {
                alert('Gagal mengubah status: ' + (data.detail || 'Terjadi kesalahan'));
            }
        } catch (err) {
            alert('Kesalahan jaringan: ' + err.message);
        }
    };

    // 8. Delete Installation dengan Konfirmasi & Relational Guard
    let pendingDeleteInstId = null;
    window.confirmDeleteInstallation = function(instId, instName) {
        pendingDeleteInstId = instId;
        document.getElementById('delInstName').innerText = instName;
        openModal('modalDeleteInstallation');
    };

    const btnExecuteDeleteInst = document.getElementById('btnExecuteDeleteInst');
    if (btnExecuteDeleteInst) {
        btnExecuteDeleteInst.addEventListener('click', async () => {
            if (!pendingDeleteInstId) return;

            btnExecuteDeleteInst.disabled = true;
            btnExecuteDeleteInst.innerText = 'Menghapus...';

            try {
                const res = await fetch(`/api/v1/installations/${pendingDeleteInstId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-CSRF-Token': window.getCsrfToken()
                    },
                    credentials: 'same-origin'
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Instalasi berhasil dihapus.');
                    window.location.reload();
                } else {
                    alert('Gagal menghapus instalasi:\n' + (data.detail || 'Terjadi kesalahan sistem.'));
                }
            } catch (err) {
                alert('Kesalahan jaringan: ' + err.message);
            } finally {
                btnExecuteDeleteInst.disabled = false;
                btnExecuteDeleteInst.innerText = 'Ya, Hapus Instalasi';
                closeModal('modalDeleteInstallation');
                pendingDeleteInstId = null;
            }
        });
    }

});
