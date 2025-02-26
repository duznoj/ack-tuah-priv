<h1 align="center">Headers Parsing</h1>

Now that we're receiving packets. These are of the form:

<pre align ="center">
 -----------
| IP Header |
|-----------|
|           |
|IP Payload |
|           |
 -----------
</pre>

We can parse the IP Header using <a href="https://datatracker.ietf.org/doc/html/rfc791#section-3.1" target="_blank">RFC 791: Section 3.1</a>

We define a "packed" IPv4 Header struct, a packed header means that the compiler doesn't add any padding between the fields of the struct.


Now create an instance of this struct and fill it from the packet. To get the values of some of the fields you might need to do some bitwise operations.

Note that all these fields are stored in Network Byte Order (Big Endian), so we have to make sure we're interacting with this data in a proper manner. I am building this on a Little-Endian machine, and while I am trying to write the code in an endianness-agnostic way. I still might miss something.

From the IP header, we'll skip packets which aren't IPv4, and also any packets which are not Protocol `0x06` (TCP).


Now we can calculate the the offset to the beginning of the IP Payload, i.e, the start of the TCP Segment.

Now in a similar fashion we create a TCP header struct. Parse out the TCP header.

And then get the offset to the beginning of the TCP Payload, i.e, the start of the Application Layer Data.

To maintain a record of the state in which a connection between the local device and the remote device. We'll maintain a HashMap of a quad-tuple struct of (local_ip, local_port, remote_ip, remote_port) as keys to some sort of a connection state struct.

###### HashMaps in C:
HashMaps are not a part of the C Standard Library, so there are no in-built implementations of a HashMap. Now we could build our own HashMap implementation, but building a good general-purpose HashMap implementation would become an entire project itself.

For now, we'll use troydhanson's <a href="https://troydhanson.github.io/uthash/" target="_blank">uthash</a> library and create some functions around the macros that uthash provides.
