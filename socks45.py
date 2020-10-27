import asyncio
import logging
import socket
import traceback
import platform
from struct import unpack , pack


logging.basicConfig(level=logging.WARNING)


READ_MAX_SIZE = 65535
BUFFER_SIZE_LIMIT = 500_000
MAX_QUEUED_CONNECTIONS = 1000  # backlog
TIMEOUT = 30  # Time before closing innactive connections

bindip = None  # a local ip we will bind to (optional)



if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # https://github.com/saghul/aiodns/issues/78

elif platform.system() == "Linux":
    try:
        import uvloop
        uvloop.install()
    except ImportError:
        print("You can install uvloop for better performance")
    except:
        print("Error : Uvloop was not loaded")
        traceback.print_exc()


try:
    import aiodns
except ImportError:
    class aiodns:
        def __getattribute__(self,name):
            return

    print("Optional package aiodns not loaded")


try:
    from async_timeout import timeout
except ImportError:
    TIMEOUT = None
    print("Optional package async_timeout not loaded")



class NoDNS(Exception):
    """Aiodns was not Imported"""
    pass


class Proxy:

    def __init__(self , ip, port, readsize, buffsize, backlog, con_timeout):
        self.ip = ip
        self.port = port
        self.buffsize = buffsize
        self.readsize = readsize
        self.backlog = backlog
        self.resolver = None
        self.timeout = con_timeout


    async def passthrought(self, reader , writer):
        while True:
            if TIMEOUT:
                async with timeout(self.timeout):
                    data = await reader.read(self.readsize)
            else:
                data = await reader.read(self.readsize)

            if not data:
                writer.close()
                return

            writer.write(data)
            await writer.drain()


    @staticmethod
    async def send_replie5(writer , ver , rep , rsv , atyp , addr , port):
        writer.write(pack(">BBBB" , ver , rep , rsv , atyp))
        writer.write(socket.inet_pton((socket.AF_INET if atyp == 1 else socket.AF_INET6) , addr))
        writer.write(pack(">H" , port))
        await writer.drain()


    @staticmethod
    async def send_replie4(writer , vn , cd , dstip , dstport):
        writer.write(pack(">BB" , vn , cd))
        writer.write(dstport)
        writer.write(dstip)
        await writer.drain()


    async def handler(self , reader , writer):
        try:
            addr = writer.get_extra_info('peername')
            logging.info(f'New connection from {addr}')

            ver = await reader.readexactly(1)

            if ver == b'\x05':
                await reader.read(1024)
                writer.write(b'\x05\x00')  # Socks V5, No auth
                await writer.drain()

                data = await reader.readexactly(4)
                ver , cmd , rsv , atyp = unpack('>BBBB' , data)

                if atyp == 1:  # IPV4
                    data = await reader.readexactly(4)
                    dstaddr = socket.inet_ntoa(data)

                elif atyp == 2:  # IPV6
                    data = await reader.readexactly(16)
                    dstaddr = socket.inet_ntop(socket.AF_INET6 , data)

                elif atyp == 3:  # Domain name
                    data = await reader.readexactly(1)
                    length = unpack('>B' , data)[0]
                    dstaddress = await reader.readexactly(length)

                    if self.resolver:
                        dstaddr = (await self.resolver.gethostbyname(dstaddress.decode() , socket.AF_INET)).addresses[0]
                        atyp = 1
                    else:
                        dstaddr = 0

                else:
                    logging.warning(f"Invalid address type : {atyp} ,  data : {data}")
                    writer.close()
                    return


                data = await reader.readexactly(2)
                dstport , = unpack('>H' , data)

                if cmd == 1:
                    try:
                        if dstaddr == 0:
                            raise NoDNS

                        conreader , conwriter = await asyncio.open_connection(dstaddr , dstport, limit=self.buffsize)
                        remoteaddr = conwriter.get_extra_info('peername')

                    except ConnectionRefusedError:
                        await self.send_replie5(writer , 5 , 5 , 0 , atyp , dstaddr , dstport)
                        writer.close()
                        return

                    except NoDNS:
                        logging.warning("client sent domain name but DNS is disabled")
                        await self.send_replie5(writer , 5 , 8 , 0 , atyp , dstaddr , dstport)
                        writer.close()
                        return

                    except OSError:
                        await self.send_replie5(writer , 5 , 1 , 0 , atyp , dstaddr , dstport)
                        writer.close()
                        return


                elif cmd == 3:
                    conreader , conwriter = await asyncio.open_connection(dstaddr , dstport ,
                                                                          limit=self.buffsize,
                                                                          protocol_factory=asyncio.DatagramProtocol()
                                                                          )

                    remoteaddr = conwriter.get_extra_info('peername')

                else:
                    logging.warning(f"Unsuported CMD : {cmd} ")
                    await self.send_replie5(writer , 5 , 7 , 0 , atyp , dstaddr , dstport)
                    writer.close()
                    return


                await self.send_replie5(writer , 5 , 0 , 0 , atyp , remoteaddr[0] , remoteaddr[1])


            elif ver == b'\x04':  # Socks4 client
                cmd = await reader.readexactly(1)

                if not cmd == b'\x01':
                    logging.warning("Command not supported : "+str(cmd))
                    writer.close()
                    return

                else:
                    rawport = await reader.readexactly(2)
                    dstport , = unpack('>H' , rawport)

                    rawip = await reader.readexactly(4)
                    dstaddr = socket.inet_ntoa(rawip)

                    # Ignore the userid (we don't need it and it is often not set by clients)
                    await reader.read(1024)

                    conreader , conwriter = await asyncio.open_connection(dstaddr , dstport , limit=self.buffsize)

                    await self.send_replie4(writer, 0, 90, rawip, rawport)

            else:
                logging.warning(f"Invalid request by {addr}")
                writer.close()
                return



            local_to_remote = self.passthrought(reader , conwriter)
            remote_to_local = self.passthrought(conreader , writer)

            await asyncio.gather(local_to_remote , remote_to_local)


        except ConnectionResetError:
            logging.warning(f"Connection got reset while connecting to {dstaddr}:{dstport} on behalf {addr}")

        except ConnectionAbortedError:
            logging.warning(f"Conection was aborted by host computer when connecting to {dstaddr}:{dstport} on behalf of {addr}")
            
        except TimeoutError:
            logging.warning(f"Connection Timed out while connecting to {dstaddr}:{dstport} on behalf of {addr}")
        
        except aiodns.error.DNSError:
            logging.warning(f"DNS resolution error, failed to resolve : {dstaddress} on behalf of {addr}")
            
        except asyncio.exceptions.TimeoutError:
            logging.warning(f"Timeout reading from socket for {addr}")
        
        except asyncio.exceptions.IncompleteReadError:
            logging.warning(f"Connection on behalf of {addr} was Aborted")

        except OSError:
            traceback.print_exc()

        finally:
            logging.info(f"Closing the connection with {addr}")
            writer.close()


    async def start(self):
        try:
            self.resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        except Exception as e:
            logging.warning("DNS not enabled : "+str(e))

        server = await asyncio.start_server(self.handler , self.ip , self.port , backlog=self.backlog, limit=self.buffsize)

        addr = server.sockets[0].getsockname()
        print(f'Serving on {addr}')

        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    proxy = Proxy('127.0.0.1', 8888, READ_MAX_SIZE, BUFFER_SIZE_LIMIT, MAX_QUEUED_CONNECTIONS, TIMEOUT)
    asyncio.run(proxy.start())
