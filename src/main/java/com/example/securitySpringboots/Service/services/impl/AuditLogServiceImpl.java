package com.example.securitySpringboots.Service.services.impl;


import com.example.securitySpringboots.Entity.AuditLog;
import com.example.securitySpringboots.Entity.Notes;
import com.example.securitySpringboots.Repository.AuditLogRepository;
import com.example.securitySpringboots.Service.services.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Override
    public void logNoteCreation(String username, Notes notes) {
        AuditLog log = new AuditLog();
        log.setUsername(username);
        log.setAction("CREATION");
        log.setNoteId(notes.getId());
        log.setNoteContent(notes.getContent());
        log.setTimestamp(LocalDateTime.now());
        System.out.println(notes.getId());
        auditLogRepository.save(log);
    }

    @Override
    public void logNoteUpdate(String username, Notes notes) {
        AuditLog log = new AuditLog();
        log.setUsername(username);
        log.setAction("UPDATE");
        log.setNoteId(notes.getId());
        log.setNoteContent(notes.getContent());
        log.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(log);
    }

    @Override
    public void logNoteDeletion(String username, Long noteId) {
        AuditLog log = new AuditLog();
        log.setUsername(username);
        log.setAction("DELETE");
        log.setNoteId(noteId);
        log.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(log);
    }

    @Override
    public List<AuditLog> getAllAudit() {
        return auditLogRepository.findAll();
    }

    @Override
    public List<AuditLog> getAuditLogsForNoteId(Long noteId) {
        return auditLogRepository.findByNoteId(noteId);
    }
}
