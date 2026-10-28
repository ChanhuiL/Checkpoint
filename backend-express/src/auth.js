import { ApiError } from "./errors.js";
import jwt from "jsonwebtoken";

// jsonwebtoken은 설치되어 있습니다. 아래 함수의 본문을 구현하세요.
export function issueToken(user) {
  // TODO BE-01: 서버 환경변수 키로 HS256 JWT 발급. sub, exp, iss, aud 필수.
  const payload = 
  {
	sub: user.id,
	iss: process.env.JWT_ISSUER,
	aud: process.env.JWT_AUDIENCE
  }
  const token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn: `${process.env.TOKEN_TTL}s`})
  return token
}
export function currentUserId(req) {
  // TODO BE-02: Bearer 추출 → 서명/알고리즘/만료/클레임 검증 → 실제 사용자 확인.
  // 완성 후 아래 데모 ID 반환을 제거하세요. 토큰 없음/변조/만료는 401입니다.

  const authHeader = req.headers['authorization'];
  if (!authHeader)
	throw new ApiError(401, "TOKEN_REQUIRED", "JWT 토큰이 존재하지 않습니다.");
  if (!authHeader.startsWith('Bearer '))
	throw new ApiError(401, "TOKEN_REQUIRED", "Bearer 헤더 형식을 확인할 수 없습니다.");
  const token = authHeader.split(' ')[1];
  try {
	const payload = jwt.verify(token, process.env.JWT_SECRET)
	return payload.sub
  } catch(err) {
    throw new ApiError(401, "INVALID_TOKEN", "사용자를 확인할 수 없습니다.");
	// return null
  }
}
export function assertOwner(userId, authorId) {
  // TODO BE-03: 다른 작성자이면 403 FORBIDDEN. 현재는 검사하지 않습니다.
  if (userId != authorId){
	throw new ApiError(403, "FORBIDDEN", "올바르지 않은 사용자입니다.")
  }
}
