package com.multi.travel.domain.place.entity;

/*
 * Please explain the class!!!
 *
 * @filename    : Place
 * @author      : Choi MinHyeok
 * @since       : 25. 12. 1. 월요일
 */

import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.util.Date;

@Entity
@Table(name = "tb_plc")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class Place {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private Long contentId;

    @Column
    private String title;

    @Column
    private String address;

    @Column
    private String tel;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(precision = 13, scale = 10)
    private BigDecimal mapx;  // 경도

    @Column(precision = 13, scale = 10)
    private BigDecimal mapy;  // 위도

    @Column
    private String placeType;

    @Column
    private String parking;

    @Column
    private String timeAvailable;

    @Column
    private String openTime;

    @Column
    private String restDate;

    @Column
    private String bestMenu;

    @Column
    private String checkIn;

    @Column
    private String checkOut;

    @Column
    private Date createdAt;

    @Column
    private Date updatedAt;

    @Column
    private int viewCount;

}
