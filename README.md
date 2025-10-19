1. Thông tin chung
•	Tên dự án: Triển khai hệ thống thu thập và phân tích thông tin tình báo mối đe dọa.
•	Mục tiêu chính: Xây dựng một quy trình tự động hoàn chỉnh, sử dụng T-Pot để thu thập dữ liệu tấn công (IoC) và tích hợp vào nền tảng Threat Intelligence (MISP) để phân tích, quản lý.
•	Tập trung vào: 
•	Triển khai T-Pot để thu thập IoC từ các cuộc tấn công thực tế trên Internet.
•	Xây dựng script (Python) để tự động hóa việc trích xuất và phân tích IoC từ T-Pot.
•	Tích hợp IoC vào MISP thông qua API để tập trung hóa và quản lý thông tin.
2. Nhiệm vụ và yêu cầu chi tiết
2.1. Yêu cầu chung:
1.	Chạy thử nghiệm dự án: Các máy ảo của hệ thống phải được triển khai và hoạt động ổn định, có thể truy cập để kiểm tra.
2.2. Nhiệm vụ chi tiết:
A. Giai đoạn 1: Xây dựng nền tảng 
•	Nghiên cứu & Thiết kế:
•	Nghiên cứu kiến trúc của T-Pot, vai trò của ELK Stack.
•	Nghiên cứu mô hình dữ liệu của MISP (Event, Attribute).
•	Vẽ sơ đồ kiến trúc hệ thống tổng thể.
•	Triển khai môi trường:
•	Cài đặt và cấu hình 03 máy ảo: T-Pot, MISP, Scripting Server.
•	Thiết lập mạng, IP tĩnh và các quy tắc firewall cần thiết.
•	Cấu hình T-Pot:
•	Cài đặt T-Pot thành công.
•	Cấu hình Port Forwarding trên router để "phơi" T-Pot ra Internet và bắt đầu thu thập dữ liệu.
B. Giai đoạn 2: Tích hợp và Tự động hóa 
•	Phân tích và Trích xuất IoC từ T-Pot:
•	Sử dụng Kibana để khám phá, phân tích cấu trúc log trong Elasticsearch.
•	Viết script Python để kết nối vào Elasticsearch, truy vấn và trích xuất các IoC tiềm năng (IP nguồn, username/password, hash mã độc...). 
•	Tích hợp IoC vào MISP:
•	Nghiên cứu thư viện PyMISP và API của MISP. 
•	Hoàn thiện script để tự động đẩy các IoC đã trích xuất vào MISP, tạo thành các Events và Attributes tương ứng.
•	Tự động hóa:
•	Thiết lập cơ chế chạy tự động, định kỳ cho script (sử dụng cron job).
2.3. Công nghệ sử dụng:
•	Honeypot Platform: T-Pot Community Edition
•	Threat Intelligence Platform: MISP
•	Ngôn ngữ Scripting: Python 3
•	Cơ sở dữ liệu (T-Pot): Elasticsearch
•	Hệ điều hành: Debian 11 (cho T-Pot), Ubuntu Server 22.04 hoặc CentOS9 (cho MISP & Scripting)
•	Nền tảng ảo hóa: VMware / VirtualBox
3. Phân công công việc:
•	Học viên: Chịu trách nhiệm toàn bộ các nhiệm vụ từ nghiên cứu, thiết kế, triển khai hạ tầng, viết code tích hợp đến báo cáo và demo sản phẩm. 
4. Tiêu chí đánh giá:
•	Chức năng hoạt động: Hệ thống phải hoạt động tự động, ổn định. Dữ liệu tấn công mới trên T-Pot phải được cập nhật lên MISP. 
•	Chất lượng code: Cấu trúc script rõ ràng, dễ hiểu, có chú thích đầy đủ. 
•	Quản lý Git: Lịch sử commit đầy đủ, rõ ràng, thể hiện được quá trình làm việc. 
•	Báo cáo: Tài liệu trình bày logic, đầy đủ các hạng mục và đúng hạn. 
•	Demo: Trình bày và demo thành công toàn bộ luồng hoạt động của hệ thống. 

