syntax = "proto3";

package api;


message Task {
    string id = 1;
    string link = 2;
    string request_time = 3;
    string status = 4;
    string content = 5;
    string http_headers = 6;
    bool robot_status = 7;
    string robot_cashe = 8;
}

message CreateTaskRequest {
    string task_link = 1;
}

message CreateTaskResponse {
    Task task = 1; // will have a task id
}

message ReadTaskRequest {
    string task_id = 1;
}

message ReadTaskResponse {
    Task task = 1;
}

message UpdateTaskRequest {
    string task_id = 1;
}

message UpdateTaskResponse {
    Task task = 1;
}

message DeleteTaskRequest {
    string task_id = 1;
}

message DeleteTaskResponse {
    string task_id = 1;
}

message ListTaskRequest {

}

message ListTaskResponse {
    Task task = 1;
}



service TaskService {
    rpc CreateTask (CreateTaskRequest) returns (CreateTaskResponse){}
    rpc ReadTask (ReadTaskRequest) returns (ReadTaskResponse){} // return NOT_FOUND if not found
    rpc UpdateTask (UpdateTaskRequest) returns (UpdateTaskResponse){} // return NOT_FOUND if not found
    rpc DeleteTask (DeleteTaskRequest) returns (DeleteTaskResponse){} // return NOT_FOUND if not found
    rpc ListTask (ListTaskRequest) returns (stream ListTaskResponse){}
}
