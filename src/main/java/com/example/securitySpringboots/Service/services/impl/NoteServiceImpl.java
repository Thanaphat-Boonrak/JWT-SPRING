package com.example.securitySpringboots.Service.services.impl;

import com.example.securitySpringboots.Entity.Notes;
import com.example.securitySpringboots.Repository.NotesRepository;
import com.example.securitySpringboots.Service.services.AuditLogService;
import com.example.securitySpringboots.Service.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class NoteServiceImpl implements NoteService {

    @Autowired
    private NotesRepository noteRepository;

    @Autowired
    private AuditLogService auditLogService;

    @Override
    public Notes createNoteForUser(String username, String content) {
        Notes note = new Notes();
        note.setContent(content);
        note.setOwnerUsername(username);
        Notes savedNote = noteRepository.save(note);
        auditLogService.logNoteCreation(username,note);
        return savedNote;
    }

    @Override
    public Notes updateNoteForUser(Long noteId, String content, String username) {
        Notes note = noteRepository.findById(noteId).orElseThrow(()
                -> new RuntimeException("Note not found"));
        note.setContent(content);
        Notes updateNote = noteRepository.save(note);
        auditLogService.logNoteUpdate(username,note);
        return updateNote;
    }

    @Override
    public void deleteNoteForUser(Long noteId, String username) {
        Notes note = noteRepository.findById(noteId).orElseThrow(() -> new RuntimeException("Note not found"));
        auditLogService.logNoteDeletion(username,noteId);
        noteRepository.deleteById(noteId);
    }

    @Override
    public List<Notes> getNotesForUser(String username) {
        return noteRepository
                .findByownerUsername(username);
    }
}


