// main.go
package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/stephencryyy/crypt/web/grpcclient"
	"github.com/stephencryyy/crypt/web/handlers"
	"github.com/stephencryyy/crypt/web/middleware"
)

func main() {
	grpcclient.InitGRPCClient()
	defer grpcclient.CloseGRPC()

	// Получаем DSN из переменных окружения или используем значение по умолчанию
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		// На случай запуска локально без docker-compose:
		dsn = "postgres://postgres:mysecretpassword@localhost:5432/mydb?sslmode=disable"
	}

	// Инициализируем БД до запуска роутера
	if err := handlers.InitializeDB(dsn); err != nil {
		log.Fatalf("Не удалось инициализировать БД: %v", err)
	}

	router := gin.Default()

	// Загрузка HTML-шаблонов (убедитесь, что путь корректен)
	router.LoadHTMLGlob("templates/*")

	// Обслуживание статических файлов (убедитесь, что путь корректен)
	router.Static("/static", "./static")

	// Главная страница (landing page)
	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "home.html", nil)
	})

	// Маршруты для авторизации
	router.GET("/register", func(c *gin.Context) {
		c.HTML(200, "register.html", nil)
	})
	router.POST("/register", handlers.Register)

	router.GET("/login", func(c *gin.Context) {
		c.HTML(200, "login.html", nil)
	})
	router.POST("/login", handlers.Login)

	// Группа маршрутов, требующих авторизации
	authorized := router.Group("/messi")
	authorized.Use(middleware.AuthMiddleware())
	{
		// Маршрут для меню чатов
		authorized.GET("/hub", handlers.MenuHandler)

		// Маршрут для отображения страницы чата с room_id
		authorized.GET("/chat", handlers.ChatHandler) // /messi/chat?room_id=...

		// Маршрут для отображения страницы создания чата (GET)
		authorized.GET("/create_chat", handlers.ShowCreateChatPage)

		// Маршрут для обработки создания чата (POST)
		authorized.POST("/create_chat", handlers.CreateChat)

		// Маршрут для присоединения к чату (POST)
		authorized.POST("/join_chat", handlers.JoinChat)

		// WebSocket маршрут
		authorized.GET("/ws", handlers.WebSocketHandler)

		// Маршруты для отправки и управления приглашениями
		authorized.POST("/send_invitation", handlers.SendInvitationHandler)
		authorized.GET("/invitations", handlers.ListInvitationsHandler)
		authorized.POST("/respond_invitation", handlers.RespondInvitationHandler)

		// Маршрут для выхода из профиля
		authorized.GET("/logout", handlers.LogoutHandler)

		// Маршрут для отправки файла
		authorized.POST("/chat/send-file", handlers.SendFileHandler)
		authorized.GET("/chat/files", handlers.ListFilesHandler)
		authorized.GET("/chat/download-file", handlers.DownloadFileHandler)

		// Маршрут для удаления чата
		authorized.DELETE("/chat", handlers.DeleteChatHandler)
	}

	// Запуск сервера на порту 8080
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Не удалось запустить сервер: %v", err)
	}
}
