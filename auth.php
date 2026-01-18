<?php
/**
 * Rhymix Auth API (API Key 보안 강화 버전)
 */
define('__ZBX__', true);
require_once(__DIR__ . '/config/config.inc.php');
$oContext = Context::getInstance();
$oContext->init();

// --- [보안 설정] ---
// 이 키는 절대로 외부에 노출되지 않도록 주의하세요.
$MY_SECRET_KEY = 'your_super_secret_api_key_2026'; 

// 헤더에서 API Key 추출 (PHP에서는 HTTP_ 접두사가 붙습니다)
$received_key = $_SERVER['HTTP_X_API_KEY'] ?? '';

if ($received_key !== $MY_SECRET_KEY) {
    header('HTTP/1.1 403 Forbidden');
    echo json_encode(['status' => 'error', 'message' => 'Access denied']);
    exit;
}
// ------------------

$input = json_decode(file_get_contents('php://input'), true);
$user_id = $input['user_id'] ?? '';
$password = $input['password'] ?? '';

header('Content-Type: application/json; charset=utf-8');

$oMemberModel = getModel('member');
$member_info = $oMemberModel->getMemberInfoByUserID($user_id);

if ($member_info && $oMemberModel->isValidPassword($member_info->password, $password)) {
    echo json_encode([
        'status' => 'success',
        'data' => [
            'member_srl' => $member_info->member_srl,
            'user_id' => $member_info->user_id,
            'nick_name' => $member_info->nick_name,
            'email' => $member_info->email_address,
            'server' => $member_info->server, 
        ]
    ]);
} else {
    // Brute-force 지연을 위해 0.5초 대기
    usleep(500000);
    echo json_encode(['status' => 'error', 'message' => 'Access denied']);
}