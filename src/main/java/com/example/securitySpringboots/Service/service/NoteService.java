package com.example.securitySpringboots.Service.service;

import com.example.securitySpringboots.Entity.Notes;

import java.util.List;

public interface NoteService {
    Notes createNoteForUser(String username, String content);

    Notes updateNoteForUser(Long noteId, String content, String username);

    void deleteNoteForUser(Long noteId, String username);

    List<Notes> getNotesForUser(String username);
}
