/**
 * Rhymix CMS & Node.js Integration Final Middleware
 * - Authentication: Rhymix PHP (isValidPassword)
 * - Security: Shared API Key (X-API-KEY)
 * - Session: JSON Web Token (JWT)
 */

const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

const app = express();
const PORT = 3000;

// --- [보안 및 환경 설정] ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ⚠️ 실무에서는 아래 키들을 .env 파일에 보관하는 것을 권장합니다.
const RHYMIX_AUTH_URL = 'http://localhost/auth.php'; // PHP 파일 위치
const API_SECRET_KEY = 'your_super_secret_api_key_2026'; // PHP와 동일하게 설정
const JWT_SECRET = 'node_jwt_access_secret_key_999'; // JWT 서명용 키

// 1. Swagger UI 설정 (http://localhost:3000/api-docs)
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

/**
 * 2. JWT 검증 미들웨어
 * 보호된 경로에 접근할 때 클라이언트의 토큰을 확인합니다.
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

    if (!token) return res.status(401).json({ message: '인증 토큰이 없습니다.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: '유효하지 않거나 만료된 토큰입니다.' });
        req.user = user;
        next();
    });
};

/**
 * 3. [POST] /auth/login
 * 라이믹스 CMS 인증 후 JWT 토큰을 발급합니다.
 */
app.post('/auth/login', async (req, res) => {
    const { user_id, password } = req.body;

    if (!user_id || !password) {
        return res.status(400).json({ message: '아이디와 비밀번호를 입력해주세요.' });
    }

    try {
        // [핵심] 라이믹스 PHP API 호출 (API Key 포함)
        const response = await axios.post(RHYMIX_AUTH_URL, 
            { user_id, password }, 
            {
                headers: { 
                    'X-API-KEY': API_SECRET_KEY,
                    'Content-Type': 'application/json'
                },
                timeout: 5000 // 5초 응답 지연 시 타임아웃
            }
        );

        if (response.data.status === 'success') {
            const userData = response.data.data;

            // JWT 토큰 생성 (유효기간 2시간)
            const accessToken = jwt.sign(
                { 
                    member_srl: userData.member_srl, 
                    user_id: userData.user_id,
                    nick_name: userData.nick_name,
                    server: userData.server
                },
                JWT_SECRET,
                { expiresIn: '2h' }
            );

            // 최종 성공 응답
            return res.json({
                message: '로그인 성공',
                accessToken: accessToken,
                user: userData
            });
        } else {
            return res.status(401).json({ message: response.data.message });
        }
    } catch (error) {
        // 에러 상세 로그 (서버 콘솔 전용)
        console.error('Auth Bridge Error:', error.message);
        
        if (error.response && error.response.status === 403) {
            return res.status(403).json({ message: 'API 접근 거부 (Key 불일치)' });
        }
        return res.status(500).json({ message: '인증 서버 통신 중 오류가 발생했습니다.' });
    }
});

/**
 * 4. [GET] /auth/me
 * 로그인 상태 확인용 보호된 경로
 */
app.get('/auth/me', authenticateToken, (req, res) => {
    res.json({
        message: '토큰이 유효합니다.',
        user: req.user
    });
});

// --- [서버 기동] ---
app.listen(PORT, () => {
    console.log('------------------------------------------------');
    console.log(`✅ API Middleware Server is running on port ${PORT}`);
    console.log(`📄 API Documentation: http://localhost:${PORT}/api-docs`);
    console.log('------------------------------------------------');
});