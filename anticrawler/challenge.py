"""
挑战验证模块 - 验证码和JavaScript挑战
"""
import time
import hashlib
import secrets
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import json


@dataclass
class ChallengeResult:
    """挑战结果"""
    required: bool
    challenge_type: Optional[str] = None
    challenge_data: Optional[Dict] = None
    verified: bool = False


class ChallengeManager:
    """挑战验证管理器"""
    
    def __init__(self, config):
        self.config = config
        self.challenges = {}  # session_id -> challenge_data
        self.verified_sessions = {}  # session_id -> verify_time
    
    def should_challenge(self, ip: str, risk_score: float, fingerprint_score: float) -> ChallengeResult:
        """判断是否需要挑战"""
        total_score = (risk_score + fingerprint_score) / 2
        
        # 检查是否已验证
        if self._is_verified(ip):
            return ChallengeResult(required=False, verified=True)
        
        # 分数超过阈值需要挑战
        if total_score >= self.config.challenge_threshold:
            challenge_type = self._select_challenge_type(total_score)
            challenge_data = self._generate_challenge(ip, challenge_type)
            
            return ChallengeResult(
                required=True,
                challenge_type=challenge_type,
                challenge_data=challenge_data
            )
        
        return ChallengeResult(required=False)
    
    def verify_challenge(self, ip: str, challenge_id: str, response: str) -> bool:
        """验证挑战响应"""
        if ip not in self.challenges:
            return False
        
        challenge = self.challenges[ip]
        
        # 检查挑战ID
        if challenge.get('id') != challenge_id:
            return False
        
        # 检查是否过期
        if time.time() > challenge.get('expires_at', 0):
            del self.challenges[ip]
            return False
        
        # 验证响应
        challenge_type = challenge.get('type')
        verified = False
        
        if challenge_type == 'js_challenge':
            verified = self._verify_js_challenge(challenge, response)
        elif challenge_type == 'math_challenge':
            verified = self._verify_math_challenge(challenge, response)
        elif challenge_type == 'token_challenge':
            verified = self._verify_token_challenge(challenge, response)
        
        if verified:
            # 标记为已验证
            self.verified_sessions[ip] = time.time()
            del self.challenges[ip]
        
        return verified
    
    def _is_verified(self, ip: str) -> bool:
        """检查是否已验证且在有效期内"""
        if ip not in self.verified_sessions:
            return False
        
        verify_time = self.verified_sessions[ip]
        if time.time() - verify_time > self.config.challenge_duration:
            del self.verified_sessions[ip]
            return False
        
        return True
    
    def _select_challenge_type(self, score: float) -> str:
        """根据分数选择挑战类型"""
        if score >= 80:
            return 'js_challenge'  # 高难度JavaScript挑战
        elif score >= 60:
            return 'math_challenge'  # 数学题
        else:
            return 'token_challenge'  # 简单令牌验证
    
    def _generate_challenge(self, ip: str, challenge_type: str) -> Dict:
        """生成挑战"""
        challenge_id = secrets.token_urlsafe(16)
        expires_at = time.time() + 300  # 5分钟过期
        
        if challenge_type == 'js_challenge':
            # JavaScript计算挑战
            nonce = secrets.token_hex(8)
            difficulty = 6  # 需要找到前6位为0的哈希
            challenge = {
                'id': challenge_id,
                'type': challenge_type,
                'expires_at': expires_at,
                'nonce': nonce,
                'difficulty': difficulty,
                'prefix': '0' * difficulty
            }
            self.challenges[ip] = challenge
            return {
                'challenge_id': challenge_id,
                'nonce': nonce,
                'difficulty': difficulty
            }
        
        elif challenge_type == 'math_challenge':
            # 数学题
            import random
            a = random.randint(10, 99)
            b = random.randint(10, 99)
            answer = a + b
            challenge = {
                'id': challenge_id,
                'type': challenge_type,
                'expires_at': expires_at,
                'answer': str(answer)
            }
            self.challenges[ip] = challenge
            return {
                'challenge_id': challenge_id,
                'question': f'{a} + {b} = ?'
            }
        
        else:  # token_challenge
            # 令牌验证
            token = secrets.token_hex(16)
            challenge = {
                'id': challenge_id,
                'type': challenge_type,
                'expires_at': expires_at,
                'token': token
            }
            self.challenges[ip] = challenge
            return {
                'challenge_id': challenge_id,
                'token': token
            }
    
    def _verify_js_challenge(self, challenge: Dict, response: str) -> bool:
        """验证JavaScript挑战"""
        # response应该是找到的nonce值
        nonce = challenge.get('nonce')
        difficulty = challenge.get('difficulty', 6)
        prefix = '0' * difficulty
        
        # 验证哈希
        test_string = f"{nonce}:{response}"
        hash_result = hashlib.sha256(test_string.encode()).hexdigest()
        
        return hash_result.startswith(prefix)
    
    def _verify_math_challenge(self, challenge: Dict, response: str) -> bool:
        """验证数学题挑战"""
        return response.strip() == challenge.get('answer')
    
    def _verify_token_challenge(self, challenge: Dict, response: str) -> bool:
        """验证令牌挑战"""
        return response.strip() == challenge.get('token')
    
    def get_challenge_page(self, challenge_data: Dict, challenge_type: str) -> str:
        """生成挑战页面HTML"""
        if challenge_type == 'js_challenge':
            return self._generate_js_challenge_page(challenge_data)
        elif challenge_type == 'math_challenge':
            return self._generate_math_challenge_page(challenge_data)
        else:
            return self._generate_token_challenge_page(challenge_data)
    
    def _generate_js_challenge_page(self, data: Dict) -> str:
        """生成JavaScript挑战页面"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>验证中...</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
        }}
        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        h2 {{ color: #333; }}
        p {{ color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>正在验证您的身份...</h2>
        <div class="spinner"></div>
        <p>请稍候，这可能需要几秒钟</p>
    </div>
    <script>
        const nonce = '{data['nonce']}';
        const difficulty = {data['difficulty']};
        const challengeId = '{data['challenge_id']}';
        
        // 计算Proof of Work
        function findProofOfWork() {{
            const prefix = '0'.repeat(difficulty);
            let solution = 0;
            
            while (true) {{
                const testString = nonce + ':' + solution;
                const hash = sha256(testString);
                
                if (hash.startsWith(prefix)) {{
                    return solution;
                }}
                solution++;
            }}
        }}
        
        // SHA256实现
        function sha256(message) {{
            // 简化的SHA256实现
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return hashHex;
        }}
        
        // 异步执行
        async function solve() {{
            const solution = await findProofOfWork();
            
            // 提交答案
            fetch('/verify-challenge', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{
                    challenge_id: challengeId,
                    response: solution.toString()
                }})
            }}).then(() => {{
                window.location.reload();
            }});
        }}
        
        solve();
    </script>
</body>
</html>
"""
    
    def _generate_math_challenge_page(self, data: Dict) -> str:
        """生成数学题挑战页面"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>人机验证</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            text-align: center;
        }}
        input {{
            padding: 10px;
            font-size: 16px;
            border: 2px solid #ddd;
            border-radius: 5px;
            width: 100px;
            text-align: center;
        }}
        button {{
            padding: 10px 30px;
            font-size: 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-left: 10px;
        }}
        button:hover {{ background: #764ba2; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>请完成验证</h2>
        <p style="font-size: 24px; margin: 20px 0;">{data['question']}</p>
        <form method="POST" action="/verify-challenge">
            <input type="hidden" name="challenge_id" value="{data['challenge_id']}">
            <input type="number" name="response" required autofocus>
            <button type="submit">验证</button>
        </form>
    </div>
</body>
</html>
"""
    
    def _generate_token_challenge_page(self, data: Dict) -> str:
        """生成令牌挑战页面"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>人机验证</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .token {{
            font-family: monospace;
            font-size: 18px;
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            letter-spacing: 2px;
        }}
        button {{
            padding: 15px 40px;
            font-size: 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }}
        button:hover {{ background: #764ba2; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>请复制以下令牌并点击验证</h2>
        <div class="token">{data['token']}</div>
        <form method="POST" action="/verify-challenge">
            <input type="hidden" name="challenge_id" value="{data['challenge_id']}">
            <input type="hidden" name="response" value="{data['token']}">
            <button type="submit">我是人类</button>
        </form>
    </div>
</body>
</html>
"""
