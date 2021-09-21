Curso: Spring Boot Microservices
https://www.youtube.com/playlist?list=PL62G310vn6nH_iMQoPMhIlK_ey1npyUUl
Aulas: 11

sem impendimento
NETFLIX Eureka
###########################
https://start.spring.io/
###########################
sudo systemctl stop tomcat.service
########################### Aula-01
postgres yml stack
https://hub.docker.com/_/postgres
https://hub.docker.com/_/mysql

cd projetos/java/cursos/devdojo/course-devdojo-microservices/idbcourse
sudo docker-compose -f stack.yml up
sudo docker-compose -f stack.yml down

########################### OBS
Criei a conexão mysql e depois o banco devdojo

########################### Aula-02
mv clean install -DskipTests (n rodei, só o clean e install mesmo)

########################### Aula-03
Rodar na sequência:
discovery
course
gateway
auth
eureka -> http://localhost:8081/

########################### Aula-04
http://www.unit-conversion.info/texttools/random-string-generator/

########################### Aula-05
https://jwt.io/
Rodar na sequência:
discovery
gateway
auth
course

password gerado no test do auth, colocar no banco
senhha: $2a$10$xu/HdZGnOwc96xlFSs8iJ.snuWFMiUHfkIJqCZDye.4Od0fCX1PcC
INSERT INTO devdojo.application_user
(id, password, `role`, username)
VALUES(1, '$2a$10$xu/HdZGnOwc96xlFSs8iJ.snuWFMiUHfkIJqCZDye.4Od0fCX1PcC', 'ADMIN', 'devdojo');


########################### Aula-09
http://localhost:8080/gateway/auth/swagger-ui.html
http://localhost:8080/gateway/course/swagger-ui.html

##################################################### Tentar depois com postgres
# Use postgres/example user/password credentials
version: '3.1'

services:

  db:
    image: postgres
#Reinicia o volume    
    #restart: always
    ports:
      - 8080:8080
    environment:
      POSTGRES_USER: root
      POSTGRES_PASSWORD: 210184
    volumes:
      - microservices_devdojo:/var/lib/mysql

volumes:
  microservices_devdojo:

#  adminer:
#    image: adminer
#    restart: always
#    ports:
#####################################################      
    