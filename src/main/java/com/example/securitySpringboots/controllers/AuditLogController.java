package com.example.securitySpringboots.controllers;

import com.example.securitySpringboots.Entity.AuditLog;
import com.example.securitySpringboots.Service.service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/audit")
public class AuditLogController {

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping
    public List<AuditLog> getAuditLog() {
        return auditLogService.getAllAudit();
    }

    @GetMapping("/audit/{id}")
    public List<AuditLog> getAuditLogById(@PathVariable Long id) {
        return  auditLogService.getAuditLogsForNoteId(id);
    }

}
