import requests
import time
import re
import os
import logging
import json
from urllib.parse import urlparse, unquote, parse_qs

# Thư viện GeoIP
try:
    import geoip2.database
    GEOIP_ENABLED = True
except ImportError:
    logging.warning("Không tìm thấy thư viện geoip2. Chức năng định vị địa lý sẽ bị tắt.")
    GEOIP_ENABLED = False

# --- Cấu hình ---
# Lấy các biến này từ GitHub Secrets
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHANNEL_ID = os.environ.get('TELEGRAM_CHANNEL_ID') # ID kênh của bạn (ví dụ: -100123456789)

# Đường dẫn tệp tương đối so với vị trí thực thi tập lệnh (thư mục gốc của repo trong GitHub Actions)
SUBSCRIPTION_FILE = 'data/subscriptions.txt'
ARCHIVE_FILE = 'data/archive.txt'
# Đường dẫn đã cập nhật cho cơ sở dữ liệu GeoLite2 Country
GEOIP_DATABASE_PATH = 'data/GeoLite2-Country.mmdb'

POST_DELAY_SECONDS = 600 # Độ trễ giữa các bài đăng (ví dụ: 600 giây = 10 phút)
PROXIES_PER_POST = 9 # Số lượng proxy trong mỗi tin nhắn Telegram
MAX_EXECUTION_TIME_SECONDS = 3300 # Thời gian thực thi tối đa tính bằng giây (55 phút)

# Ngưỡng độ dài cho heuristic secret (secret dài hơn ngưỡng này có đuôi 'A' sẽ bị bỏ qua)
# Secret ngắn hơn ngưỡng này có đuôi 'A' sẽ được cắt bớt 'A'.
# Được điều chỉnh dựa trên phản hồi của người dùng và danh sách proxy được cung cấp.
SECRET_HEURISTIC_LENGTH_THRESHOLD = 60 # Ngưỡng đã điều chỉnh

# URL cơ sở của Telegram Bot API
TELEGRAM_API_URL = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}'

# --- Thiết lập Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Thiết lập GeoIP ---
geoip_reader = None
if GEOIP_ENABLED:
    if os.path.exists(GEOIP_DATABASE_PATH):
        try:
            # Sử dụng geoip2.database.Reader cho cơ sở dữ liệu Country
            geoip_reader = geoip2.database.Reader(GEOIP_DATABASE_PATH)
            logging.info("Tải cơ sở dữ liệu GeoIP Country thành công.")
        except Exception as e:
            logging.error(f"Lỗi khi tải cơ sở dữ liệu GeoIP Country: {e}")
            geoip_reader = None # Tắt GeoIP nếu tải thất bại
            GEOIP_ENABLED = False
    else:
        logging.warning(f"Không tìm thấy cơ sở dữ liệu GeoIP Country tại {GEOIP_DATABASE_PATH}. Chức năng định vị địa lý sẽ bị tắt.")
        GEOIP_ENABLED = False


def get_geolocation(ip_address):
    """Tra cứu định vị quốc gia cho địa chỉ IP bằng cơ sở dữ liệu GeoIP đã tải."""
    if not GEOIP_ENABLED or not geoip_reader:
        return 'Không xác định', '', '' # Trả về tên quốc gia, biểu tượng cảm xúc trống, mã trống

    try:
        # Sử dụng phương thức country cho cơ sở dữ liệu GeoLite2-Country
        response = geoip_reader.country(ip_address)
        country_name = response.country.name if response.country else 'Không xác định'
        country_code = response.country.iso_code if response.country else '' # Lấy mã quốc gia
        country_emoji = get_country_emoji(country_code) if country_code else ''
        return country_name, country_emoji, country_code # Trả về tên, biểu tượng cảm xúc và mã
    except geoip2.errors.AddressNotFoundError:
        logging.debug(f"Không tìm thấy định vị địa lý cho IP: {ip_address}")
        return 'Không xác định', '', ''
    except Exception as e:
        logging.error(f"Lỗi trong quá trình tra cứu GeoIP cho {ip_address}: {e}")
        return 'Không xác định', '', ''

def get_country_emoji(country_code):
    """Chuyển đổi mã quốc gia ISO 3166-1 alpha-2 thành biểu tượng cảm xúc cờ."""
    if not country_code or len(country_code) != 2:
        return ''
    # Biểu tượng cảm xúc cờ được biểu thị bằng hai ký hiệu chỉ báo vùng.
    # Các chữ cái ký hiệu chỉ báo vùng là các ký tự Unicode từ U+1F1E6 đến U+1F1FF.
    # 'A' là U+1F1E6, 'B' là U+1F1E7, v.v.
    # Vì vậy, biểu tượng cảm xúc cho mã quốc gia như 'US' là U+1F1FA U+1F1F8
    # (Ký hiệu chỉ báo vùng chữ U + Ký hiệu chỉ báo vùng chữ S)
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in country_code.upper())

def process_secret_with_heuristic(secret):
    """
    Áp dụng một heuristic để xử lý secret dựa trên các ký tự 'A' ở cuối và độ dài.
    - Nếu secret kết thúc bằng 'A' và ngắn hơn ngưỡng, cắt bỏ các ký tự 'A'.
    - Nếu secret kết thúc bằng 'A' và dài hơn hoặc bằng ngưỡng, trả về None (bỏ qua).
    - Ngược lại, trả về secret gốc.
    """
    if not secret:
        return secret # Trả về secret trống như ban đầu

    # Tìm chỉ số của ký tự không phải 'A' đầu tiên từ cuối
    last_non_a_index = len(secret) - 1
    while last_non_a_index >= 0 and secret[last_non_a_index] == 'A':
        last_non_a_index -= 1

    # Nếu secret chỉ bao gồm các ký tự 'A' hoặc trống sau khi cắt
    if last_non_a_index < 0:
        # Nếu secret gốc chỉ là 'A's, nó có thể không hợp lệ, coi là bị hỏng
        logging.debug(f"Secret '{secret}' chỉ bao gồm các ký tự 'A'. Coi là bị hỏng và bỏ qua.")
        return None

    trimmed_secret = secret[:last_non_a_index + 1]
    trailing_as_count = len(secret) - len(trimmed_secret)

    # Nếu có các ký tự 'A' ở cuối
    if trailing_as_count > 0:
        logging.debug(f"Secret '{secret}' có {trailing_as_count} ký tự 'A' ở cuối. Phần đã cắt: '{secret[last_non_a_index+1:]}'")
        # Áp dụng heuristic độ dài dựa trên độ dài *gốc* của secret
        if len(secret) >= SECRET_HEURISTIC_LENGTH_THRESHOLD:
            logging.warning(f"Secret gốc '{secret}' dài ({len(secret)} ký tự) và có ký tự 'A' ở cuối. Coi là bị hỏng và bỏ qua.")
            return None # Bỏ qua các secret dài có ký tự 'A' ở cuối
        else:
            logging.info(f"Secret gốc '{secret}' ngắn ({len(secret)} ký tự) và có ký tự 'A' ở cuối. Sử dụng secret đã cắt: '{trimmed_secret}'")
            return trimmed_secret # Sử dụng secret đã cắt cho các secret ngắn hơn

    # Nếu không có ký tự 'A' ở cuối, trả về secret gốc
    return secret


# --- Các hàm hỗ trợ ---

def get_proxies_from_links(file_path):
    """Đọc các liên kết đăng ký từ tệp và tìm nạp các chuỗi proxy thô."""
    raw_proxies = []
    try:
        with open(file_path, 'r') as f:
            links = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"Không tìm thấy tệp đăng ký tại {file_path}")
        return raw_proxies

    logging.info(f"Đang tìm nạp proxy từ {len(links)} liên kết đăng ký...")
    for link in links:
        try:
            response = requests.get(link, timeout=15) # Thời gian chờ để tìm nạp liên kết
            response.raise_for_status() # Gây ra HTTPError cho các phản hồi xấu (4xx hoặc 5xx)
            content = response.text

            # Giả định các liên kết đăng ký cung cấp danh sách các liên kết tg:// hoặc https://t.me/proxy
            # Chia nội dung theo dòng và lọc các liên kết liên quan
            proxy_links_from_link = [
                line.strip() for line in content.splitlines()
                if line.strip().startswith('tg://proxy?') or line.strip().startswith('https://t.me/proxy?')
            ]
            logging.info(f"Đã tìm nạp {len(proxy_links_from_link)} liên kết proxy Telegram từ {link}")
            raw_proxies.extend(proxy_links_from_link)

        except requests.exceptions.RequestException as e:
            logging.error(f"Lỗi khi tìm nạp proxy từ {link}: {e}")
        except Exception as e:
            logging.error(f"Đã xảy ra lỗi không mong muốn khi xử lý {link}: {e}")

    # Lọc bỏ các chuỗi trống và các tiêu đề/bình luận tiềm năng
    raw_proxies = [p.strip() for p in raw_proxies if p.strip() and not p.strip().startswith('#')]
    logging.info(f"Tổng số liên kết proxy Telegram thô đã tìm nạp: {len(raw_proxies)}")
    return raw_proxies


def parse_telegram_proxy_link(proxy_link):
    """
    Phân tích một liên kết proxy Telegram (tg://proxy? hoặc https://t.me/proxy?).
    Trích xuất server, port và secret. Xử lý secret bằng heuristic.
    Trả về một từ điển với các chi tiết đã phân tích, bao gồm 'raw' với secret đã xử lý,
    hoặc None nếu phân tích/xử lý thất bại hoặc heuristic bỏ qua proxy.
    """
    parsed = {'original_raw': proxy_link, 'type': 'Telegram'} # Lưu liên kết thô gốc

    try:
        # Chuyển đổi https://t.me/proxy? thành tg://proxy? để phân tích nhất quán
        if proxy_link.startswith('https://t.me/proxy?'):
            link_to_parse = 'tg://proxy?' + proxy_link.split('?', 1)[1]
        elif proxy_link.startswith('tg://proxy?'):
            link_to_parse = proxy_link
        else:
            logging.warning(f"Định dạng liên kết không được hỗ trợ để phân tích: {proxy_link}")
            return None

        parsed_url = urlparse(link_to_parse)
        query_params = parse_qs(parsed_url.query)

        server = query_params.get('server', [None])[0]
        port = query_params.get('port', [None])[0]
        secret = query_params.get('secret', [None])[0]

        # --- Kiểm tra tham số cơ bản ---
        # Kiểm tra xem tham số server hoặc port có bị thiếu (None) không
        if server is None or port is None:
            logging.warning(f"Thiếu tham số server hoặc port trong liên kết: {proxy_link}")
            return None

        # --- Xử lý Secret bằng Heuristic ---
        # Nếu tham số secret bị thiếu (None), process_secret_with_heuristic sẽ xử lý nó.
        processed_secret = process_secret_with_heuristic(secret)

        # Nếu process_secret_with_heuristic trả về None, bỏ qua proxy này
        if processed_secret is None:
            logging.warning(f"Heuristic xử lý secret dẫn đến việc bỏ qua liên kết: {proxy_link}")
            return None

        parsed['ip'] = server
        parsed['port'] = port
        parsed['secret'] = processed_secret # Sử dụng secret đã xử lý

        # Lấy định vị địa lý (Tên quốc gia, biểu tượng cảm xúc và mã)
        country_name, country_emoji, country_code = get_geolocation(parsed['ip'])
        parsed['country'] = country_name
        parsed['country_emoji'] = country_emoji
        parsed['country_code'] = country_code # Lưu mã quốc gia

        # --- Xây dựng lại liên kết thô với secret đã xử lý ---
        # Điều này rất quan trọng để liên kết thô được sử dụng cho siêu liên kết và nút
        # chứa secret có thể đã được cắt bớt.
        if processed_secret is not None: # Không nên là None nếu chúng ta đến đây, nhưng là một thực hành tốt
            parsed['raw'] = f"tg://proxy?server={parsed['ip']}&port={parsed['port']}&secret={processed_secret}"
            # Nếu có thẻ, hãy đưa nó vào liên kết đã xây dựng lại
            if 'tag' in query_params and query_params['tag'][0] is not None:
                parsed['raw'] += f"&tag={query_params['tag'][0]}"


        logging.debug(f"Đã phân tích liên kết proxy Telegram: {parsed}")
        return parsed

    except Exception as e:
        logging.error(f"Lỗi khi phân tích liên kết proxy Telegram {proxy_link}: {e}")
        return None

def check_proxy(proxy_details):
    """
    Đối với proxy Telegram, chúng ta không thể thực hiện kiểm tra kết nối tiêu chuẩn
    với requests. Hàm này chủ yếu xác nhận việc phân tích đã thành công.
    """
    if proxy_details and proxy_details.get('type') == 'Telegram':
        # Đánh dấu là đã phân tích thành công, nhưng chưa kiểm tra kết nối
        proxy_details['status'] = 'parsed'
        proxy_details['latency'] = -1 # Không áp dụng
        return proxy_details
    else:
        # Không nên xảy ra nếu get_proxies_from_links và parse_telegram_proxy_link hoạt động chính xác
        return None


def load_archive(file_path):
    """Tải các proxy đã được *xử lý* đã đăng trước đó từ tệp lưu trữ."""
    archived_proxies = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                # Tải các liên kết thô đã được xử lý đã lưu trước đó
                archived_proxies = {line.strip() for line in f if line.strip()}
            logging.info(f"Đã tải {len(archived_proxies)} proxy đã xử lý từ kho lưu trữ.")
        except Exception as e:
            logging.error(f"Lỗi khi tải tệp lưu trữ {file_path}: {e}")
    else:
        logging.info("Không tìm thấy tệp lưu trữ. Bắt đầu với một kho lưu trữ trống.")
    return archived_proxies

def save_archive(file_path, new_processed_proxies):
    """Thêm các proxy đã được *xử lý* mới đăng vào tệp lưu trữ."""
    if not new_processed_proxies:
        return

    try:
        with open(file_path, 'a') as f:
            # Lưu các liên kết thô đã xử lý
            for proxy_string in new_processed_proxies:
                f.write(proxy_string + '\n')
        logging.info(f"Đã lưu {len(new_processed_proxies)} proxy đã xử lý mới vào kho lưu trữ.")
    except Exception as e:
        logging.error(f"Lỗi khi lưu vào tệp lưu trữ {file_path}: {e}")

def escape_markdown_v2(text):
    """Thoát các ký tự đặc biệt của MarkdownV2."""
    # Xem https://core.telegram.org/bots/api#markdownv2-style
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(r'([%s])' % re.escape(escape_chars), r'\\\1', str(text))


def post_proxies_chunk_to_telegram(chat_id, proxies_chunk):
    """Định dạng và đăng một nhóm proxy Telegram lên kênh Telegram."""
    if not proxies_chunk:
        return False

    message_lines = [
        "*🌟 PROXY BỎ CHẶN TELEGRAM 🌟*\n",
        "_Proxy chất lượng cao \- Tốc độ nhanh \- Bảo mật tuyệt đối_\n",
        "*Hướng dẫn sử dụng:*\n",
        "1\. Nhấn nút 'Kết nối' bên dưới\n",
        "2\. Chọn 'Mở trong Telegram'\n",
        "3\. Nhấn 'Start Using This Proxy'\n\n",
        "*Proxy được cập nhật mỗi giờ để đảm bảo hoạt động tốt nhất\!*\n\n"
    ]
    inline_buttons = []

    # Xây dựng nội dung tin nhắn và thu thập dữ liệu nút cho mỗi proxy trong nhóm
    for i, proxy_details in enumerate(proxies_chunk):
        # --- Chuẩn bị dữ liệu cho nút nội tuyến "Connect" với biểu tượng cờ quốc gia ---
        country_emoji = proxy_details.get('country_emoji', '')
        button_text = f"Kết nối {country_emoji}" if country_emoji else "Kết nối"
        # Sử dụng liên kết thô có thể đã được sửa đổi cho URL nút
        button_url = proxy_details.get('raw', '')

        if button_url:
            inline_buttons.append({'text': button_text, 'url': button_url})


    # Thêm tên kênh vào cuối tin nhắn
    message_lines.append("\n@MinionGroup1")


    message_text = "\n".join(message_lines)

    # Tạo đánh dấu bàn phím nội tuyến
    reply_markup = None
    if inline_buttons:
        # --- Bố cục nút: Lưới 3x3 ---
        inline_keyboard = []
        row = []
        for i, button in enumerate(inline_buttons):
            row.append(button)
            # Bắt đầu một hàng mới sau mỗi 3 nút, hoặc nếu đó là nút cuối cùng
            if (i + 1) % 3 == 0 or (i + 1) == len(inline_buttons):
                inline_keyboard.append(row)
                row = [] # Bắt đầu một danh sách hàng mới

        reply_markup = json.dumps({'inline_keyboard': inline_keyboard})


    # --- Gửi tin nhắn bằng requests ---
    send_message_url = f'{TELEGRAM_API_URL}/sendMessage'
    payload = {
        'chat_id': chat_id,
        'text': message_text,
        'parse_mode': 'MarkdownV2',
        'reply_markup': reply_markup # Thêm bàn phím nội tuyến
    }

    # Xóa reply_markup nếu nó là None để tránh gửi tham số
    if reply_markup is None:
        del payload['reply_markup']


    logging.info(f"Đang cố gắng đăng một nhóm {len(proxies_chunk)} proxy lên chat ID {chat_id}...")
    try:
        response = requests.post(send_message_url, json=payload)
        response.raise_for_status() # Gây ra HTTPError cho các phản hồi xấu (4xx hoặc 5xx)
        logging.info(f"Đã đăng thành công một nhóm {len(proxies_chunk)} proxy lên Telegram. Mã trạng thái: {response.status_code}")
        logging.debug(f"Phản hồi API Telegram: {response.text}") # Ghi log phản hồi đầy đủ để gỡ lỗi
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi khi đăng nhóm proxy lên Telegram: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logging.error(f"Mã trạng thái lỗi phản hồi API Telegram: {e.response.status_code}")
            logging.error(f"Nội dung phản hồi lỗi API Telegram: {e.response.text}")
            try:
                error_response = e.response.json()
                if 'error_code' in error_response and error_response['error_code'] == 429: # Quá nhiều yêu cầu (Flood)
                    logging.warning("Vượt quá giới hạn kiểm soát Flood. Đang chờ lâu hơn trước khi đăng bài tiếp theo.")
                    time.sleep(60) # Chờ thêm một phút khi có lỗi flood
            except:
                pass # Bỏ qua lỗi phân tích JSON nếu phản hồi không phải là JSON

        return False
    except Exception as e:
        logging.error(f"Đã xảy ra lỗi không mong muốn trong quá trình đăng Telegram: {e}")
        return False


# --- Thực thi chính ---

def main():
    # Ghi lại thời gian bắt đầu thực thi
    start_time = time.time()

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHANNEL_ID:
        logging.error("Các biến môi trường TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHANNEL_ID chưa được đặt.")
        logging.error("Vui lòng đặt các biến này làm GitHub Secrets.")
        return

    # 1. Lấy các liên kết proxy Telegram thô từ các liên kết đăng ký
    raw_telegram_proxy_links = get_proxies_from_links(SUBSCRIPTION_FILE)

    if not raw_telegram_proxy_links:
        logging.info("Không tìm nạp được liên kết proxy Telegram thô nào. Đang thoát.")
        return

    # 2. Tải kho lưu trữ các proxy đã được *xử lý* đã đăng trước đó
    archived_processed_proxies = load_archive(ARCHIVE_FILE)
    logging.info(f"Đã tải {len(archived_processed_proxies)} proxy đã xử lý từ kho lưu trữ.")


    # 3. Phân tích và xử lý tất cả các liên kết đã tìm nạp, và lọc so với kho lưu trữ (dựa trên liên kết đã xử lý)
    logging.info("Đang phân tích và xử lý các liên kết proxy Telegram đã tìm nạp...")
    proxies_to_post = []
    processed_links_encountered = set() # Sử dụng một set để theo dõi các liên kết đã xử lý gặp trong lần chạy này

    for original_raw_link in raw_telegram_proxy_links:
        # Kiểm tra xem việc phân tích liên kết này có vượt quá giới hạn thời gian không
        elapsed_time = time.time() - start_time
        if elapsed_time + 5 > MAX_EXECUTION_TIME_SECONDS: # Thêm một vùng đệm (ví dụ: 5 giây)
            logging.warning(f"Thời gian thực thi gần đạt giới hạn ({MAX_EXECUTION_TIME_SECONDS}s) trong quá trình phân tích. Bỏ qua các liên kết còn lại.")
            break # Dừng phân tích nếu thời gian sắp hết

        # Phân tích và xử lý liên kết (heuristic secret được áp dụng, parsed['raw'] được cập nhật)
        proxy_details = parse_telegram_proxy_link(original_raw_link)

        # Nếu việc phân tích và xử lý thành công
        if proxy_details:
            processed_raw_link = proxy_details['raw']

            # Kiểm tra xem liên kết đã xử lý này đã được gặp trong lần chạy này chưa (khử trùng lặp trong lần tìm nạp hiện tại)
            if processed_raw_link in processed_links_encountered:
                logging.debug(f"Bỏ qua liên kết đã xử lý trùng lặp gặp trong lần chạy này: {processed_raw_link}")
                continue # Chuyển sang liên kết tiếp theo

            # Kiểm tra xem liên kết đã xử lý này đã có trong kho lưu trữ chưa (khử trùng lặp so với lịch sử)
            if processed_raw_link in archived_processed_proxies:
                logging.debug(f"Bỏ qua liên kết đã xử lý đã tìm thấy trong kho lưu trữ: {processed_raw_link}")
                # Thêm liên kết đã xử lý vào tập hợp các liên kết gặp trong lần chạy này, ngay cả khi đã lưu trữ,
                # để xử lý các trường hợp liên kết đã xử lý tương tự xuất hiện nhiều lần trong nguồn.
                processed_links_encountered.add(processed_raw_link)
                continue # Chuyển sang liên kết tiếp theo


            # Nếu liên kết đã xử lý là mới (chưa gặp trong lần chạy này hoặc trong kho lưu trữ)
            logging.debug(f"Tìm thấy liên kết đã xử lý mới có thể đăng: {processed_raw_link}")
            processed_proxy = check_proxy(proxy_details) # Điều này chỉ đặt trạng thái thành 'parsed'
            if processed_proxy:
                proxies_to_post.append(processed_proxy)
                # Thêm liên kết đã xử lý vào tập hợp các liên kết gặp trong lần chạy này
                processed_links_encountered.add(processed_raw_link)


    logging.info(f"Đã tìm thấy {len(proxies_to_post)} proxy mới, duy nhất và hợp lệ có thể đăng sau khi lọc.")


    if not proxies_to_post:
        logging.info("Không có proxy mới để đăng sau khi lọc. Đang thoát.")
        # Nếu không có proxy mới, vẫn lưu kho lưu trữ trong trường hợp có bất kỳ liên kết đã xử lý mới nào được gặp
        # mà không có trong kho lưu trữ (mặc dù chúng sẽ không được đăng).
        # Tuy nhiên, cách tiếp cận đáng tin cậy nhất là chỉ lưu trữ các liên kết đã được đăng thành công.
        # Chúng ta sẽ giữ nguyên việc chỉ lưu trữ các liên kết đã đăng thành công.
        return

    # 4. Chia nhóm và đăng proxies_to_post lên Telegram với độ trễ
    logging.info(f"Bắt đầu quá trình đăng cho {len(proxies_to_post)} proxy theo nhóm {PROXIES_PER_POST} với độ trễ {POST_DELAY_SECONDS} giây giữa các nhóm...")

    posted_chunks_count = 0
    proxies_actually_posted_processed_links = [] # Theo dõi các liên kết thô đã được *xử lý* đã đăng thành công

    # Lặp lại các proxy_to_post theo nhóm
    for i in range(0, len(proxies_to_post), PROXIES_PER_POST):
        chunk = proxies_to_post[i:i + PROXIES_PER_POST]
        logging.info(f"Đang xử lý nhóm bắt đầu với proxy {i+1} (chứa {len(chunk)} proxy).")

        # Tính toán thời gian cần thiết cho bài đăng này và độ trễ tiếp theo
        time_needed_for_post = 5 # Ước tính thời gian cho cuộc gọi API (có thể thay đổi)
        if (i + PROXIES_PER_POST) < len(proxies_to_post):
            time_needed_for_post += POST_DELAY_SECONDS # Thêm độ trễ nếu không phải là nhóm cuối cùng

        # Kiểm tra xem việc đăng nhóm này và chờ có vượt quá giới hạn thời gian không
        elapsed_time = time.time() - start_time
        if elapsed_time + time_needed_for_post > MAX_EXECUTION_TIME_SECONDS:
            logging.warning(f"Thời gian thực thi gần đạt giới hạn ({MAX_EXECUTION_TIME_SECONDS}s) trong quá trình đăng. Bỏ qua các bài đăng còn lại.")
            break # Dừng đăng nếu thời gian sắp hết

        success = post_proxies_chunk_to_telegram(TELEGRAM_CHANNEL_ID, chunk)

        if success:
            posted_chunks_count += 1
            # Thêm các liên kết thô đã được *xử lý* từ các proxy trong nhóm này vào danh sách các liên kết đã được đăng thực sự
            proxies_actually_posted_processed_links.extend([p['raw'] for p in chunk])
            # Chờ trước khi đăng nhóm tiếp theo, trừ khi đó là nhóm cuối cùng
            if (i + PROXIES_PER_POST) < len(proxies_to_post):
                logging.info(f"Đang chờ {POST_DELAY_SECONDS} giây trước nhóm tiếp theo...")
                time.sleep(POST_DELAY_SECONDS)
        else:
            logging.warning(f"Không thể đăng nhóm bắt đầu với proxy {i+1}. Bỏ qua việc chờ và chuyển sang nhóm tiếp theo.")
            # Nếu việc đăng thất bại, chúng ta có thể không muốn chờ toàn bộ độ trễ.
            # Việc xử lý lỗi flood nằm bên trong post_proxies_chunk_to_telegram.


    logging.info(f"Đã hoàn tất quá trình đăng. {posted_chunks_count} nhóm đã được đăng thành công.")
    logging.info(f"Tổng số proxy đã đăng thành công: {len(proxies_actually_posted_processed_links)}")


    # 5. Lưu các proxy thô đã được *xử lý* đã *thực sự đăng* vào kho lưu trữ
    # Điều này đảm bảo chúng ta không lưu trữ các proxy đã bị bỏ qua do hết thời gian hoặc lỗi phân tích.
    save_archive(ARCHIVE_FILE, proxies_actually_posted_processed_links)
    logging.info(f"Đã lưu trữ {len(proxies_actually_posted_processed_links)} proxy đã xử lý đã được đăng thành công.")


    # Đóng trình đọc cơ sở dữ liệu GeoIP khi tập lệnh kết thúc
    if geoip_reader:
        geoip_reader.close()

if __name__ == "__main__":
    main()
