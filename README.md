Hệ thống Tự động Thu thập và Phân tích Threat Intelligence (T-Pot -> MISP)
Dự án này xây dựng một quy trình (data pipeline) tự động hoàn chỉnh, có chức năng thu thập thông tin tình báo mối đe dọa (IoC) từ một hệ thống honeypot (T-Pot) và tự động tích hợp vào nền tảng MISP để phân tích và quản lý tập trung.

Mục tiêu chính
Triển khai T-Pot để thu thập IoC từ các cuộc tấn công thực tế trên Internet.

Xây dựng script (Python) để tự động hóa việc trích xuất và phân tích IoC từ T-Pot.

Tích hợp IoC vào MISP thông qua API để tập trung hóa và quản lý thông tin.

Kiến trúc & Luồng hoạt động (Workflow)
Hệ thống được thiết kế gồm 3 thành phần máy ảo chính: T-Pot (Honeypot), MISP (Threat Intel Platform), và Scripting Server (chứa script tự động hóa).

Luồng dữ liệu hoạt động như sau:

Thu thập (T-Pot): T-Pot được "phơi" ra Internet thông qua Port Forwarding, thu hút các cuộc tấn công và ghi log chi tiết vào Elasticsearch (ELK Stack).

Trích xuất (Script Python): Một script Python chạy định kỳ (cron job) trên Scripting Server kết nối vào Elasticsearch, truy vấn và trích xuất các IoC tiềm năng (IP nguồn, username/password, hash mã độc...).

Tích hợp (MISP): Script sử dụng thư viện PyMISP để đẩy các IoC đã trích xuất vào MISP, tự động tạo các Events và Attributes tương ứng để quản lý và phân tích.

Công nghệ sử dụng
Honeypot Platform: T-Pot Community Edition

Threat Intelligence Platform: MISP

Ngôn ngữ Scripting: Python 3

Thư viện: elasticsearch-py (để truy vấn T-Pot), pymisp (để đẩy dữ liệu lên MISP)

Cơ sở dữ liệu (T-Pot): Elasticsearch

Hệ điều hành: Debian 11 (T-Pot), Ubuntu Server 22.04 (MISP & Scripting Server)

Nền tảng ảo hóa: VMware / VirtualBox
