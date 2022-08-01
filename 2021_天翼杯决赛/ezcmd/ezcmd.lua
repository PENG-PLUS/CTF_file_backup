-- 入口函数
function main()
    local s = Server("ez engine")
    s:print_logo()
    s:init()
    s:run()
end

function Server(name)
    local self = {}
    local function ServerInit()
        self.name = name
        self.user = 'admin'
        self.password = 'null'

        self.init = server_init
        self.print_logo = print_logo
    end

    self.info = function()
        print("Server Info:")
        print("---- name: "..self.name)
    end

    self.login = function()
        print("ez engine login")
        self.is_login = login()
        if(self.is_login == 1) then
            print("登录成功")
        else 
            print("登录失败")
        end
    end

    self.run = function()
        while(true)do
            io.write("$ ")
            local t = io.read('*l')
            if(t == "info") then
                if(self.is_login == 1) then
                    self.info()
                else
                    print("login first...")
                end
            else if(t == "login") then
                self.login()
            else if(t == "help") then
                print("commands:")
                print("login")
                print("info")
                print("exit")
            else if(t == "exit")
            then
                print("exit")
                break
            else
                print("ezcmd: command not found: "..t)
            end
            end
            end
            end
        end
    end
    ServerInit()
    return self
end

