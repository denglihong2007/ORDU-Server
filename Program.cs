using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Buffers;
using System.IO.Pipelines;
using Newtonsoft.Json;
using System.Diagnostics;
#pragma warning disable CS8600, CS8602, CS8603, CS8604, CS8618, CS8625
namespace server
{
    class NetServer
    {
        //创建链表，保存连接的用户
        public static List<ClientSocket> clientSockets = new();
        public static Dictionary<string,GameServer> GameServers = new();
        //主程序调用开始
        static void Main()
        {
            try
            {
                DirectoryInfo dir = new(@"C:\Users\Administrator\Desktop\PGRM");
                FileSystemInfo[] fileinfo = dir.GetFileSystemInfos();  //返回目录中所有文件和子目录
                foreach (FileSystemInfo i in fileinfo)
                {
                    if (i.Extension == ".txt")
                    {
                        File.Delete(i.FullName);      //删除指定文件
                    }
                }
            }
            catch
            {

            }
           //创建Socket
            Socket server = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            //绑定ip
            IPAddress ip = IPAddress.Parse("0.0.0.0");

            //绑定端口
            IPEndPoint point = new(ip, 86);

            //申请可用端口号，标志着你这个服务器程序在本机的进程
            server.Bind(point);

            Console.WriteLine("服务器启动成功,欢迎使用服务器");
            server.Listen();
            //一直监听外界，保存连接过来的客户端；
            while (true)
            {
                Socket socket = server.Accept();//接受客户端连接
                Console.WriteLine(socket.RemoteEndPoint + "连接到服务器");
                ClientSocket clientSocket = new(socket);
                clientSockets.Add(clientSocket);
            }
        }

        //消息广播到所有已连接的客户端，此方法根据自己的需要使用
        public static void BroadcastMessage(string message)
        {
            List<ClientSocket> breakSocket = new();

            foreach (ClientSocket cs in clientSockets)
            {
                if (cs.Connected)
                {
                    cs.SendMessage(message);
                }
                else
                {
                    breakSocket.Add(cs);
                }
            }

            foreach (ClientSocket cs in breakSocket)
            {
                clientSockets.Remove(cs);
            }
        }//method_end
    }
    class ClientSocket
    {
        readonly Socket clientSocket;   //当前客户端在服务器的套接字
        readonly byte[] buffer = new byte[1024]; //用来缓存客户端发送的消息

        //构造函数
        public ClientSocket(Socket socket)
        {
            clientSocket = socket;
            Thread t = new(Recieve);
            t.Start();
        }

        //发送消息
        public void SendMessage(string message)
        {
            clientSocket.Send(Encoding.UTF8.GetBytes(message));
            Console.WriteLine("向" + clientSocket.RemoteEndPoint + "发送" + message);
        }
        public async void Recieve()
        {
            while (true)
            {
                try
                {
                    int length = clientSocket.Receive(buffer);
                    string message = Encoding.UTF8.GetString(buffer, 0, length);
                    if (clientSocket.Poll(1000, SelectMode.SelectRead) && (clientSocket.Available == 0))
                    {
                        Console.WriteLine("客户端" + clientSocket.RemoteEndPoint + "已断开连接");
                        clientSocket.Shutdown(SocketShutdown.Receive);
                        clientSocket.Close();
                        break;
                    }
                    Console.WriteLine("客户端" + clientSocket.RemoteEndPoint + "发送消息：" + message);
                    if (message == "GetVersion")
                    {
                        SendMessage("Version:1.3.1");
                    }
                    else if (message.Contains("NewServer"))
                    {
                        if (!NetServer.GameServers.ContainsKey(message[10..]))
                        {
                            NetServer.GameServers.Add(message[10..], new GameServer
                            {
                                Port = message[10..],
                                OwnerIP = clientSocket.RemoteEndPoint.ToString()[..clientSocket.RemoteEndPoint.ToString().IndexOf(":")]
                            });
                            SendMessage("SuccessfullyStartedTheNewServer:" + message[10..]);
                        }
                        else
                        {
                            SendMessage("ServerAlreadyExists:" + message[10..]);
                        }
                    }
                    else if (message.Contains("StopServer"))
                    {
                        if (NetServer.GameServers.TryGetValue(message[11..], out GameServer value))
                        {
                            if (value.OwnerIP == clientSocket.RemoteEndPoint.ToString()[..clientSocket.RemoteEndPoint.ToString().IndexOf(":")])
                            {
                                value.CancellationTokenSource.Cancel();
                                if (!value.Progress.IsAlive)
                                {
                                    SendMessage("ServerHasBeenStopped:" + value.Port);
                                }
                            }
                            else
                            {
                                SendMessage("InsufficientPermissions");
                            }
                        }
                    }
                    else if (message.Contains("ChangeDispatcher"))
                    {
                        if (NetServer.GameServers.TryGetValue(message.Substring(17,5), out GameServer value))
                        {
                            if (value.OwnerIP == clientSocket.RemoteEndPoint.ToString()[..clientSocket.RemoteEndPoint.ToString().IndexOf(":")])
                            {
                                value.SendToEveryone(" 21: SERVER WhoCanBeServer");
                                await Task.Delay(1000).ConfigureAwait(false);
                                value.SendToEveryone("SERVER " + message[22..]);
                                value.Dispatcher = message[22..];
                            }
                            else
                            {
                                SendMessage("InsufficientPermissions");
                            }
                        }
                    }
                    else if (message == "GetServersList")
                    {
                        SendMessage("ServersList:" + JsonConvert.SerializeObject(NetServer.GameServers.Keys));
                    }
                    else if (message.Contains("GetServerDetails"))
                    {
                        if (NetServer.GameServers.TryGetValue(message[17..],out GameServer value))
                        {
                            SendMessage("ServerDetails:" + JsonConvert.SerializeObject(value));
                        }
                    }
                    else if (message.Contains(" "))
                    {
                        Console.WriteLine("客户端" + clientSocket.RemoteEndPoint + "已断开连接");
                        clientSocket.Shutdown(SocketShutdown.Receive);
                        clientSocket.Close();
                        break;
                    }
                }
                catch (Exception e)
                {
                    if(e.Message != "远程主机强迫关闭了一个现有的连接。")
                    {
                        Console.WriteLine(e);
                    }
                    Console.WriteLine("客户端" + clientSocket.RemoteEndPoint + "已断开连接");
                    clientSocket.Shutdown(SocketShutdown.Receive);
                    clientSocket.Close();
                    break;
                }
            }
        }//method_end
        //客户端是否连接
        public bool Connected
        {
            get
            {
                return clientSocket.Connected;
            }
        }
        // 检查一个Socket是否可连接

    }
    class GameServer
    {
        [JsonIgnore]
        public string Port
        {
            get
            {
                return port.ToString();
            }
            set
            {
                port = int.Parse(value);
                Progress = new(Run);
                Progress.Start();
            }
        }
        [JsonIgnore]
        public Thread Progress { get; set; }
        [JsonIgnore]
        public string OwnerIP { get; set; }
        [JsonIgnore]
        public CancellationTokenSource CancellationTokenSource
        {
            get
            {
                return cancellationTokenSource;
            }
            set
            {
            }
        }
        public List<string>? Players 
        { 
            get
            {
                return onlinePlayers.Keys.ToList<string>();
            } 
            set 
            { 
            } 
        }
        private string log = "服务开始\n";
        private readonly CancellationTokenSource cancellationTokenSource = new();
        private int port;
        private static readonly Encoding encoding = Encoding.Unicode;
        private static readonly int charSize = encoding.GetByteCount("0");
        private readonly Dictionary<string, TcpClient> onlinePlayers = new();
        public string Dispatcher;
        public async void Run()
        {
            try
            {
                TcpListener listener = new(IPAddress.Any, port);
                listener.Start();
                while (!cancellationTokenSource.IsCancellationRequested)
                {
                    try
                    {
                        Pipe pipe = new();
                        TcpClient tcpClient = await listener.AcceptTcpClientAsync(cancellationTokenSource.Token).ConfigureAwait(false);
                        _ = PipeFillAsync(tcpClient, pipe.Writer);
                        _ = PipeReadAsync(tcpClient, pipe.Reader);
                    }
                    catch (Exception ex)
                    {
                        if(ex.Message!= "The operation was canceled.")
                        {
                            Console.WriteLine("Error" + ex);
                        }
                    }
                }
                NetServer.GameServers.Remove(port.ToString());
                listener.Stop();
            }
            catch
            {
                throw;
            }
        }
        private async Task PipeFillAsync(TcpClient tcpClient, PipeWriter writer)
        {
            const int minimumBufferSize = 1024;
            _ = Dispatcher;
            NetworkStream networkStream = tcpClient.GetStream();

            while (tcpClient.Connected)
            {
                Memory<byte> memory = writer.GetMemory(minimumBufferSize);

                int bytesRead = await networkStream.ReadAsync(memory).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    break;
                }
                writer.Advance(bytesRead);

                FlushResult result = await writer.FlushAsync().ConfigureAwait(false);

                if (result.IsCompleted)
                {
                    break;
                }
            }
            await writer.CompleteAsync().ConfigureAwait(false);
        }

        private bool ReadPlayerName(in ReadOnlySequence<byte> sequence, ref string playerName, out SequencePosition bytesProcessed)
        {
            Span<byte> playerSeparator = encoding.GetBytes(": PLAYER ").AsSpan();
            Span<byte> blankSeparator = encoding.GetBytes(" ").AsSpan();

            SequenceReader<byte> reader = new(sequence);

            if (reader.TryReadTo(out ReadOnlySequence<byte> playerPreface, playerSeparator))
            {
                if (reader.TryReadTo(out ReadOnlySequence<byte> playerNameSequence, blankSeparator))
                {
                    int maxDigits = 4;
                    if (playerPreface.GetIntFromEnd(ref maxDigits, out int length, encoding))
                    {
                        ReadOnlySequence<byte> before = sequence.Slice(0, playerPreface.Length - maxDigits * charSize);
                        foreach (ReadOnlyMemory<byte> message in before)
                        {
                            if (message.Length > 0)
                                SendToOthers(playerName, message);
                        }
                        reader.Rewind(playerSeparator.Length + playerNameSequence.Length + maxDigits * charSize);

                        if (reader.Remaining >= length * charSize)
                        {
                            string newPlayerName = playerNameSequence.GetString(encoding);
                            ReadOnlySequence<byte> playerMessage = reader.Sequence.Slice(before.Length, (length + maxDigits + 2) * charSize);
                            if (Dispatcher != playerName)
                            {
                                foreach (ReadOnlyMemory<byte> message in playerMessage)
                                {
                                    SendToPlayer(Dispatcher, message).Wait();
                                }
                            }
                            playerName = newPlayerName;
                            bytesProcessed = sequence.GetPosition(before.Length + playerMessage.Length);
                            return true;
                        }
                    }
                }
            }
            bytesProcessed = sequence.GetPosition(sequence.Length);
            return false;
        }

        private static string ReadQuitMessage(ReadOnlySequence<byte> sequence)
        {
            Span<byte> quitSeparator = encoding.GetBytes(": QUIT ").AsSpan();
            Span<byte> blankSeparator = encoding.GetBytes(" ").AsSpan();

            SequenceReader<byte> reader = new(sequence);

            if (reader.TryReadTo(out ReadOnlySequence<byte> _, quitSeparator))
            {
                if (reader.TryReadTo(out ReadOnlySequence<byte> playerName, blankSeparator))
                {
                    return playerName.GetString(encoding);
                }
            }
            return null;
        }
        private async Task PipeReadAsync(TcpClient tcpClient, PipeReader reader)
        {
            string playerName = tcpClient.Client.RemoteEndPoint.ToString();
            bool playerNameSet = false;
            string quitPlayer;
            onlinePlayers.Add(playerName, tcpClient);
            if (onlinePlayers.Count == 1)
            {
                Dispatcher = playerName;
                await SendToPlayer(playerName, encoding.GetBytes("10: SERVER YOU")).ConfigureAwait(false);
            }
            while (tcpClient.Client.Connected)
            {
                ReadResult result = await reader.ReadAsync().ConfigureAwait(false);

                ReadOnlySequence<byte> buffer = result.Buffer;

                if (!playerNameSet)
                {
                    string player = playerName;
                    if (ReadPlayerName(buffer, ref player, out SequencePosition bytesProcessed))
                    {
                        onlinePlayers.Remove(playerName);
                        if (Dispatcher == playerName)
                            Dispatcher = playerName = player;
                        else
                            playerName = player;
                        onlinePlayers.Add(playerName, tcpClient);
                        playerNameSet = true;
                    }
                    reader.AdvanceTo(bytesProcessed);
                }
                else
                {
                    if (!string.IsNullOrEmpty(quitPlayer = ReadQuitMessage(buffer)) && playerName == quitPlayer)
                        break;

                    foreach (ReadOnlyMemory<byte> message in buffer)
                    {
                        SendToOthers(playerName, message);
                    }
                    reader.AdvanceTo(buffer.End);
                }

                if (result.IsCompleted)
                {
                    break;
                }
            }
            await RemovePlayer(playerName).ConfigureAwait(false);

            await reader.CompleteAsync().ConfigureAwait(false);
        }
        public void SendToEveryone(string message)
        {
            ReadOnlyMemory<byte> buffer = encoding.GetBytes($" {message.Length}: {message}");
            Debug.WriteLine($" {message.Length}: {message}");
            log += encoding.GetString(buffer.Span).Replace("\r", Environment.NewLine, StringComparison.OrdinalIgnoreCase) + "\n";
#if !DEBUG
            File.WriteAllText(@"C:\Users\Administrator\Desktop\PGRM\" + Port + ".txt", log);
#endif
            Parallel.ForEach(onlinePlayers.Keys, async player =>
            {
                try
                {
                    TcpClient client = onlinePlayers[player];
                    NetworkStream clientStream = client.GetStream();
                    await clientStream.WriteAsync(buffer).ConfigureAwait(false);
                    await clientStream.FlushAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException || ex is SocketException || ex is InvalidOperationException)
                {
                    if (player != null)
                        await RemovePlayer(player).ConfigureAwait(false);
                }
            });
        }

        private void SendToOthers(string playerName, ReadOnlyMemory<byte> buffer)
        {
            string msg = encoding.GetString(buffer.Span).Replace("\r", Environment.NewLine, StringComparison.OrdinalIgnoreCase);
            if (msg.Contains("CHANGESERVER "))
            {
                Dispatcher = msg.Split(" ").Last();
            }
            Debug.WriteLine(msg);
            //440-443行检测是否为更改调度指令，是则在服务端同步当前调度
            log += msg + "\n";
#if !DEBUG
            File.WriteAllText(@"C:\Users\Administrator\Desktop\PGRM\" + Port + ".txt", log);
#endif
            Parallel.ForEach(onlinePlayers.Keys, async player =>
            {
                if (player != playerName)
                {
                    try
                    {
                        TcpClient client = onlinePlayers[player];
                        NetworkStream clientStream = client.GetStream();
                        await clientStream.WriteAsync(buffer).ConfigureAwait(false);
                        await clientStream.FlushAsync().ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is IOException || ex is SocketException || ex is InvalidOperationException)
                    {
                        if (playerName != null)
                            await RemovePlayer(playerName).ConfigureAwait(false);
                    }
                }
            });
        }

        private async Task SendToPlayer(string playerName, ReadOnlyMemory<byte> buffer)
        {
            log += encoding.GetString(buffer.Span).Replace("\r", Environment.NewLine, StringComparison.OrdinalIgnoreCase) + "\n";
            Debug.WriteLine(encoding.GetString(buffer.Span).Replace("\r", Environment.NewLine, StringComparison.OrdinalIgnoreCase));
#if !DEBUG
            File.WriteAllText(@"C:\Users\Administrator\Desktop\PGRM\" + Port + ".txt", log);
#endif
            try
            {
                TcpClient client = onlinePlayers[playerName];
                NetworkStream clientStream = client.GetStream();
                await clientStream.WriteAsync(buffer).ConfigureAwait(false);
                await clientStream.FlushAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is System.IO.IOException || ex is SocketException || ex is InvalidOperationException)
            {
                if (playerName != null)
                    await RemovePlayer(playerName).ConfigureAwait(false);
            }
        }

        private async Task RemovePlayer(string playerName)
        {
            if (onlinePlayers.Remove(playerName))
            {
                string lostMessage = $"LOST {playerName}";
                byte[] lostPlayer = encoding.GetBytes($" {lostMessage.Length}: {lostMessage}");
                SendToOthers(playerName, lostPlayer);
                if (Dispatcher == playerName)
                {
                    SendToOthers(playerName, encoding.GetBytes(" 21: SERVER WhoCanBeServer"));
                    await Task.Delay(5000).ConfigureAwait(false);
                    if (onlinePlayers.Count > 0)
                    {
                        SendToOthers(null, lostPlayer);
                        Dispatcher = onlinePlayers.Keys.First();
                        string appointmentMessage = $"SERVER {Dispatcher}";
                        lostPlayer = encoding.GetBytes($" {appointmentMessage.Length}: {appointmentMessage}");
                        SendToOthers(null, lostPlayer);
                    }
                    else
                    {
                        Dispatcher = null;
                    }
                }
            }
        }

    }
    public static class ReadOnlySequenceExtensions
    {
        public static bool GetIntFromEnd(in this ReadOnlySequence<byte> payload, ref int maxDigits, out int result, Encoding encoding = null)
        {
            encoding ??= Encoding.UTF8;
            int charSize = encoding.GetByteCount("0");

            if (maxDigits > 0)
            {
                if (maxDigits * charSize > payload.Length)
                    maxDigits = (int)payload.Length / charSize;
                SequencePosition position = payload.GetPosition(payload.Length - maxDigits * charSize);
                if (payload.TryGet(ref position, out ReadOnlyMemory<byte> lengthIndicator, false))
                {
                    if (int.TryParse(encoding.GetString(lengthIndicator.Span), out result))
                        return true;
                    else
                    {
                        maxDigits--;
                        return GetIntFromEnd(payload, ref maxDigits, out result, encoding);
                    }
                }
            }
            result = 0;
            return false;
        }

        public static string GetString(in this ReadOnlySequence<byte> payload, Encoding encoding = null)
        {
            encoding ??= Encoding.UTF8;

            return payload.IsSingleSegment ? encoding.GetString(payload.FirstSpan)
                : GetStringInternal(payload, encoding);

            static string GetStringInternal(in ReadOnlySequence<byte> payload, Encoding encoding)
            {
                // linearize
                int length = checked((int)payload.Length);
                byte[] oversized = ArrayPool<byte>.Shared.Rent(length);
                try
                {
                    payload.CopyTo(oversized);
                    return encoding.GetString(oversized, 0, length);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(oversized);
                }
            }
        }
    }
}