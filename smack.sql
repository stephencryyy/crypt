CREATE TABLE IF NOT EXISTS chats (
                                     id SERIAL PRIMARY KEY,
                                     chat_name TEXT NOT NULL,
                                     created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_participants (
                                                 id SERIAL PRIMARY KEY,
                                                 chat_id INT NOT NULL,
                                                 user_id INT NOT NULL,
                                                 joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                                 FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
                                                 FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                                                 UNIQUE (chat_id, user_id)
);

ALTER TABLE chats ADD COLUMN room_id TEXT UNIQUE;
TRUNCATE TABLE chat_participants RESTART IDENTITY CASCADE;

-- Удаляем столбец username, если он был добавлен
ALTER TABLE invitations DROP COLUMN IF EXISTS username;

-- Также убедитесь, что уникальное ограничение на username удалено
ALTER TABLE invitations DROP CONSTRAINT IF EXISTS invitations_username_key;


CREATE TABLE IF NOT EXISTS  users (
                                      id SERIAL PRIMARY KEY,
                                      username VARCHAR(255) UNIQUE NOT NULL,
                                      password VARCHAR(255) NOT NULL,
                                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invitations (
                                           id SERIAL PRIMARY KEY,
                                           chat_id INT NOT NULL,
                                           inviter_id INT NOT NULL,
                                           invitee_id INT NOT NULL,
                                           status VARCHAR(20) NOT NULL DEFAULT 'pending', -- Возможные значения: 'pending', 'accepted', 'declined'
                                           created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                           FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
                                           FOREIGN KEY (inviter_id) REFERENCES users(id) ON DELETE CASCADE,
                                           FOREIGN KEY (invitee_id) REFERENCES users(id) ON DELETE CASCADE
);
ALTER TABLE invitations ADD COLUMN username TEXT UNIQUE;

CREATE OR REPLACE FUNCTION check_chat_participants() RETURNS trigger AS $$
BEGIN
    IF (SELECT COUNT(*) FROM chat_participants WHERE chat_id = NEW.chat_id) >= 2 THEN
        RAISE EXCEPTION 'Чат % уже имеет двух участников', NEW.chat_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_chat_participants
    BEFORE INSERT ON chat_participants
    FOR EACH ROW
EXECUTE FUNCTION check_chat_participants();

SELECT id FROM users WHERE LOWER(username) = LOWER('poimj');



CREATE TABLE messages (
                          id SERIAL PRIMARY KEY,
                          room_id TEXT NOT NULL,
                          sender_id TEXT NOT NULL,
                          encrypted_message BYTEA NOT NULL,
                          created_at TIMESTAMP DEFAULT NOW()
);



CREATE TABLE user_private_keys (
                                   id SERIAL PRIMARY KEY,
                                   user_id INTEGER NOT NULL REFERENCES users(id),
                                   chat_id INTEGER NOT NULL REFERENCES chats(id),
                                   private_key TEXT NOT NULL, -- Зашифрованный приватный ключ в hex формате
                                   UNIQUE(user_id, chat_id)
);

CREATE TABLE IF NOT EXISTS files (
                                     id SERIAL PRIMARY KEY,              -- Уникальный идентификатор файла
                                     room_id TEXT NOT NULL,              -- Идентификатор комнаты
                                     sender_id TEXT NOT NULL,            -- Отправитель файла
                                     file_name TEXT NOT NULL,            -- Имя файла
                                     file_size BIGINT NOT NULL,          -- Размер файла в байтах
                                     encrypted_file BYTEA NOT NULL,      -- Зашифрованное содержимое файла
                                     created_at TIMESTAMP DEFAULT NOW()  -- Дата и время загрузки
);



ALTER TABLE user_private_keys DROP CONSTRAINT IF EXISTS user_private_keys_chat_id_fkey;

-- Добавьте новый внешний ключ с ON DELETE CASCADE
ALTER TABLE user_private_keys
    ADD CONSTRAINT user_private_keys_chat_id_fkey
        FOREIGN KEY (chat_id)
            REFERENCES chats(id)
            ON DELETE CASCADE;