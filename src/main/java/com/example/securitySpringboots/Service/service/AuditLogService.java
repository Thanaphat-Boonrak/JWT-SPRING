package com.example.securitySpringboots.Service.service;

import com.example.securitySpringboots.Entity.AuditLog;
import com.example.securitySpringboots.Entity.Notes;

import java.util.List;

public interface AuditLogService {

    void logNoteCreation(String username, Notes notes);

    void logNoteUpdate(String username, Notes notes);


    void logNoteDeletion(String username, Long noteId);

    List<AuditLog> getAllAudit();


    List<AuditLog> getAuditLogsForNoteId(Long noteId);
}
