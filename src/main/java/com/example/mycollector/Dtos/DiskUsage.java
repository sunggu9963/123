package com.example.mycollector.Dtos;

import lombok.Data;

@Data
public class DiskUsage {

    private String filesystem;   // 파일시스템 (예: /dev/sda1)

    private String mountPoint;   // 마운트 포인트 (예: /, /data)

    private Double total;        // 전체 용량 (GB)

    private Double used;         // 사용 용량 (GB)

    private Double usage;        // 사용률 (%)
}