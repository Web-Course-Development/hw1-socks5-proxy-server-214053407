package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {
	// קריאת מספר הפורט משורת הפקודה, ברירת המחדל היא 1080 (דרישה R6)
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	// פתיחת שרת המאזין לחיבורי TCP נכנסים
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	// לולאה אינסופית לקבלת לקוחות (דרישה R4 - טיפול במספר חיבורים במקביל)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		// פתיחת Goroutine חדש עבור כל לקוח שמתחבר
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// --- שלב 1: קריאת ברכת השלום של הלקוח ובחירת שיטת אימות ---
	header := make([]byte, 2)
	// משתמשים ב-ReadFull כדי להבטיח שנקרא בדיוק 2 בתים
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("failed to read greeting header: %v", err)
		return
	}

	version := header[0]
	nMethods := int(header[1])

	// קריאת רשימת שיטות האימות שהלקוח תומך בהן
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Printf("failed to read methods: %v", err)
		return
	}

	// וידוא שזו אכן גרסה 5 של הפרוטוקול
	if version != 0x05 {
		conn.Write([]byte{0x05, 0xFF}) // 0xFF = אין שיטות נתמכות
		return
	}

	// בדיקה האם השרת דורש אימות באמצעות שם משתמש וסיסמה (דרישה R8)
	requiredMethod := byte(0x00) // ברירת מחדל: ללא אימות
	if os.Getenv("PROXY_USER") != "" {
		requiredMethod = 0x02 // נדרש אימות משתמש/סיסמה
	}

	// חיפוש השיטה הנדרשת מתוך השיטות שהלקוח הציע
	methodFound := false
	for _, method := range methods {
		if method == requiredMethod {
			methodFound = true
			break
		}
	}

	// אם הלקוח לא תומך בשיטה שהשרת דורש, דוחים את החיבור
	if !methodFound {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	// שליחת תשובה ללקוח עם השיטה שנבחרה
	conn.Write([]byte{0x05, requiredMethod})

	// --- שלב 2: ביצוע אימות (אם נבחרה שיטת 0x02) ---
	if requiredMethod == 0x02 {
		if !authenticateUserPass(conn) {
			return // אם האימות נכשל, עוצרים כאן וסוגרים את החיבור
		}
	}

	// --- שלב 3: טיפול בבקשת ה-CONNECT והתחברות ליעד ---
	target, err := handleConnect(conn)
	if err != nil {
		log.Printf("connect error: %v", err)
		return
	}
	defer target.Close()

	// --- שלב 4: תיווך הנתונים הלוך ושוב ---
	relay(conn, target)
}

func authenticateUserPass(conn net.Conn) bool {
	// קריאת גרסת תת-הפרוטוקול (חייב להיות 0x01) ואורך שם המשתמש
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("failed to read auth header: %v", err)
		return false
	}

	version := header[0]
	usernameLen := int(header[1])

	if version != 0x01 {
		conn.Write([]byte{0x01, 0x01}) // שגיאה
		return false
	}

	// קריאת שם המשתמש
	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		log.Printf("failed to read username: %v", err)
		return false
	}

	// קריאת אורך הסיסמה
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		log.Printf("failed to read password length: %v", err)
		return false
	}

	passwordLen := int(passLenBuf[0])

	// קריאת הסיסמה
	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		log.Printf("failed to read password: %v", err)
		return false
	}

	// אימות הנתונים מול משתני הסביבה (דרישה R7)
	if string(username) == os.Getenv("PROXY_USER") &&
		string(password) == os.Getenv("PROXY_PASS") {
		conn.Write([]byte{0x01, 0x00}) // הצלחה
		return true
	}

	conn.Write([]byte{0x01, 0x01}) // כישלון באימות
	return false
}

func handleConnect(conn net.Conn) (net.Conn, error) {
	// קריאת 4 הבתים הראשונים של בקשת ה-CONNECT
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// וידוא גרסה ופקודה (0x01 = CONNECT)
	if header[0] != 0x05 {
		sendConnectReply(conn, 0x01)
		return nil, fmt.Errorf("invalid SOCKS version")
	}
	if header[1] != 0x01 {
		sendConnectReply(conn, 0x07) // פקודה לא נתמכת
		return nil, fmt.Errorf("unsupported command")
	}
	if header[2] != 0x00 {
		sendConnectReply(conn, 0x01)
		return nil, fmt.Errorf("invalid reserved byte")
	}

	var host string

	// בדיקת סוג הכתובת (ATYP)
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()

	case 0x03: // שמות דומיין (Domain Name)
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)

	default: // כתובות שאינן נתמכות (כגון IPv6)
		sendConnectReply(conn, 0x08)
		return nil, fmt.Errorf("unsupported address type")
	}

	// קריאת פורט היעד (2 בתים)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBuf) // המרה מבתים למספר

	// יצירת הכתובת המלאה והתחברות אליה
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendConnectReply(conn, 0x05) // החזרת שגיאת חיבור (Connection Refused)
		return nil, err
	}

	// החזרת תשובת הצלחה ללקוח (0x00 = Succeeded)
	sendConnectReply(conn, 0x00)
	return target, nil
}

// פונקציית עזר לשליחת מבנה התשובה הקבוע של SOCKS5
func sendConnectReply(conn net.Conn, rep byte) {
	conn.Write([]byte{
		0x05,
		rep,
		0x00,
		0x01,                   // אנו תמיד מחזירים כתובת סרק מסוג IPv4 לשם הפשטות
		0x00, 0x00, 0x00, 0x00, // כתובת מאופסת
		0x00, 0x00, // פורט מאופס
	})
}

// תיווך נתונים בשני הכיוונים במקביל
func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// תהליכון 1: מהלקוח לשרת היעד
	go func() {
		defer wg.Done()
		io.Copy(target, client)
		// שליחת אות סיום כתיבה כדי למנוע חסימה של הבקשה (כגון ב-HTTP)
		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	// תהליכון 2: משרת היעד ללקוח
	go func() {
		defer wg.Done()
		io.Copy(client, target)
		// שליחת אות סיום כתיבה ללקוח
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	// המתנה לסיום שני הכיוונים לפני שחוזרים וסוגרים את החיבורים
	wg.Wait()
}
