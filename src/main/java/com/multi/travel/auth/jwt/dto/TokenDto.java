package com.multi.travel.auth.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenDto {
    @Builder.Default
    private String grantType = "Bearer";
    private String accessToken;
    private String refreshToken;
}