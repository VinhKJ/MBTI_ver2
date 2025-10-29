/*
 * Common client-side logic for the URP MBTI web app.
 *
 * Provides:
 *  - Simple internationalisation with Vietnamese and English dictionaries.
 *  - Helper functions to set and toggle language and apply translations to the page.
 *  - Helper for API calls including automatic bearer token injection.
 *  - Functions to handle login, registration, logout and access control on pages.
 */

const translations = {
  en: {
    // General
    home_title: "Discover Your Personality",
    home_subtitle: "Take our MBTI-based tests to understand yourself better.",
    login: "Login",
    register: "Register",
    logout: "Logout",
    language: "Language",
    english: "English",
    vietnamese: "Vietnamese",
    select_language: "Select language",
    // Forms
    email: "Email",
    password: "Password",
    confirm_password: "Confirm Password",
    full_name: "Full Name",
    submit: "Submit",
    // Dashboard
    welcome: "Welcome,",
    start_test: "Start a New Test",
    select_test: "Select Test Type",
    psi32: "PSI-32 (32 items)",
    mbti70: "MBTI-70 (70 items)",
    test_history: "Previous Results",
    test_code: "Test",
    four_letters: "Type",
    date: "Date",
    no_results: "No results yet.",
    save_result: "Save Result",
    result: "Result",
    scores: "Scores",
    margins: "Margins",
    // Test pages
    instructions_psi: "Move each slider to reflect your preference. 0 means fully A, 5 means fully B.",
    instructions_mbti: "Select A or B for each question.",
    unanswered_error: "Please answer all questions before submitting.",
    // Alerts
    registration_success: "Registration successful. Please log in.",
    registration_error: "Registration failed. Email may already be registered.",
    login_error: "Login failed. Check your credentials.",
    result_saved: "Result saved.",
    result_not_saved: "Could not save result. Try logging in.",
  },
  vi: {
    home_title: "Khám Phá Tính Cách Của Bạn",
    home_subtitle: "Thực hiện bài trắc nghiệm MBTI để hiểu rõ hơn về bản thân.",
    login: "Đăng nhập",
    register: "Đăng ký",
    logout: "Đăng xuất",
    language: "Ngôn ngữ",
    english: "Tiếng Anh",
    vietnamese: "Tiếng Việt",
    select_language: "Chọn ngôn ngữ",
    email: "Email",
    password: "Mật khẩu",
    confirm_password: "Xác nhận mật khẩu",
    full_name: "Họ và tên",
    submit: "Gửi",
    welcome: "Xin chào,",
    start_test: "Bắt đầu bài mới",
    select_test: "Chọn Loại Bài Test",
    psi32: "PSI-32 (32 câu)",
    mbti70: "MBTI-70 (70 câu)",
    test_history: "Kết quả trước đó",
    test_code: "Bài",
    four_letters: "Kiểu",
    date: "Ngày",
    no_results: "Chưa có kết quả.",
    save_result: "Lưu kết quả",
    result: "Kết quả",
    scores: "Điểm số",
    margins: "Chênh lệch",
    instructions_psi: "Di chuyển thanh trượt phản ánh sở thích của bạn. 0 hoàn toàn A, 5 hoàn toàn B.",
    instructions_mbti: "Chọn A hoặc B cho mỗi câu hỏi.",
    unanswered_error: "Vui lòng trả lời tất cả câu hỏi trước khi gửi.",
    registration_success: "Đăng ký thành công. Vui lòng đăng nhập.",
    registration_error: "Đăng ký thất bại. Email có thể đã được sử dụng.",
    login_error: "Đăng nhập thất bại. Kiểm tra thông tin đăng nhập.",
    result_saved: "Đã lưu kết quả.",
    result_not_saved: "Không thể lưu kết quả. Vui lòng đăng nhập.",
  }
};

let currentLang = localStorage.getItem('lang') || 'vi';

function setLang(lang = null) {
  // nếu không truyền, lấy từ localStorage hoặc mặc định 'vi'
  if (!lang) lang = localStorage.getItem('lang') || 'vi';
  currentLang = lang;
  localStorage.setItem('lang', lang);
  translatePage();
}

function toggleLang() {
  setLang((localStorage.getItem('lang') || 'vi') === 'vi' ? 'en' : 'vi');
}

window.setLang = () => setLang();   // an toàn khi gọi không tham số
window.toggleLang = toggleLang;


function t(key) {
  return translations[currentLang][key] || key;
}

function translatePage() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const translated = t(key);
    if (el.tagName === 'INPUT' && el.getAttribute('type') === 'submit') {
      el.value = translated;
    } else {
      el.textContent = translated;
    }
  });
  // Also update title
  document.title = t(document.querySelector('title').dataset.i18n || document.title);
}

// API helper
async function api(path, options = {}) {
  const token = localStorage.getItem('token');
  const opts = Object.assign({}, options);
  opts.headers = opts.headers || {};
  if (token) {
    opts.headers['Authorization'] = 'Bearer ' + token;
  }
  if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const resp = await fetch('/api' + path, opts);
  if (resp.status === 401) {
    // token may be invalid
    localStorage.removeItem('token');
    throw new Error('Unauthorized');
  }
  const contentType = resp.headers.get('content-type');
  let data = null;
  if (contentType && contentType.indexOf('application/json') > -1) {
    data = await resp.json();
  } else {
    data = await resp.text();
  }
  if (!resp.ok) {
    throw new Error(data.detail || resp.statusText);
  }
  return data;
}

function requireAuth() {
  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = '/static/login.html';
  }
}

function logout() {
  localStorage.removeItem('token');
  window.location.href = '/static/login.html';
}

// On script load, translate the page
document.addEventListener('DOMContentLoaded', () => {
  translatePage();
});