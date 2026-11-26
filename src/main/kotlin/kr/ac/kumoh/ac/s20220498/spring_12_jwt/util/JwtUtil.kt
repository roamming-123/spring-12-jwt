package kr.ac.kumoh.ac.s20220498.spring_12_jwt.util

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import jakarta.annotation.PostConstruct
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtUtil {

    companion object {

        const val ACCESS_TOKEN_EIXPIRATION_TIME = 20L * 1000 //20초

        const val REFRESH_TOKEN_EIXPIRATION_TIME = 40L * 1000 //40초
    }

    @Value("\${jwt.secret}")
    private lateinit var base64EncodedSecretKey: String

    private lateinit var key: SecretKey

    @PostConstruct
    fun init() {
        // base64EncodedSecretKey가 주입된 후, key 초기화
        // getDecoder() 대신 getUrlDecoder() 사용
        val decodedKey = Base64.getUrlDecoder().decode(base64EncodedSecretKey)
        key = Keys.hmacShaKeyFor(decodedKey)
    }

    fun generateAccessToken(username: String): String {
        // 0.13.0 버전
        return Jwts.builder()
            .subject(username)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + ACCESS_TOKEN_EIXPIRATION_TIME))
            .signWith(key)
            .compact()
    }

    fun generateRefreshToken(username: String): String {
        // 0.13.0 버전
        return Jwts.builder()
            .subject(username)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + REFRESH_TOKEN_EIXPIRATION_TIME))
            .signWith(key)
            .compact()
    }

    fun validateToken(token: String): Boolean {
        return try {
            // Verification (진위 확인)
            val claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)

            // Validation (유효성 검증)
            claims.payload.expiration.after(Date())
        } catch (e: SecurityException) {
            // Verification 실패 (서명 위조 등)
            false
        } catch (e: ExpiredJwtException) {
            // Validation 실패 (만료된 토큰)
            false
        } catch (e: Exception) {
            false
        }
    }
}