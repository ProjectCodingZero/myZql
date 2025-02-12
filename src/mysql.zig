const std = @import("std");
const Allocator = std.mem.Allocator;

const mysql = @cImport({
    @cInclude("mysql.h");
});
const CommandsError = error{CommandsOutofSync};
const ServerError = error{
    ServerGone,
    ServerLost,
};
const UnknownError = error{UnknownError};
const DatabaseError = error{
    ConnectionLost,
    DatabaseNotFound,
    BadHost,
};
const UnexpectedError = error{Unexpected};
const MemoryError = error{OutOfMemory};
const ConnectionOptions = struct {
    auto_commit: bool = true,
    stdio: Stdio = .{
        .stdout = std.io.getStdOut().writer().any(),
        .stdin = std.io.getStdIn().reader().any(),
        .stderr = std.io.getStdErr().writer().any(),
    },
    flags: []const ClientFlags = &.{},
};
const Stdio = struct {
    stdout: std.io.AnyWriter,
    stdin: std.io.AnyReader,
    stderr: std.io.AnyWriter,
};

pub const DatabaseInfo = struct {
    host: [:0]const u8 = "localhost",
    user: [:0]const u8 = "root",
    password: [:0]const u8 = "1234",
    database: [:0]const u8,
    port: u32 = 3306,
};
const MYSQL_C = mysql.MYSQL;
const MYSQL_STMT_C = mysql.MYSQL_STMT;
pub const Connection = struct {
    //This field is for deinit function
    pointer: *const MYSQL_C,
    connection: [*c]MYSQL_C,
    allocator: Allocator,
    stdio: Stdio,
    //Flags are constant when connection is initialize
    flags: *const c_ulong,

    pub fn init(db_info: DatabaseInfo, options: ConnectionOptions, allocator: Allocator) (DatabaseError || MemoryError)!*Connection {
        //To use memory allocation
        const allocatedDB = try allocator.create(MYSQL_C);
        errdefer allocator.destroy(allocatedDB);

        const db = mysql.mysql_init(allocatedDB);

        const flags = ClientFlags.bitMask(options.flags);
        const conn =
            mysql.mysql_real_connect(
            db,
            db_info.host,
            db_info.user,
            db_info.password,
            db_info.database,
            db_info.port,
            null,
            flags,
        );

        //setting autocommit
        if (conn != null) {
            return alloc: {
                const allocated = try allocator.create(Connection);
                allocated.* = Connection{
                    .pointer = allocatedDB,
                    .connection = db,
                    .allocator = allocator,
                    .flags = &flags,
                    .stdio = options.stdio,
                };
                allocated.autoCommit(options.auto_commit);
                break :alloc allocated;
            };
        } else {
            options.stdio.stderr.print("Connect to database failed: {s}\n", .{mysql.mysql_error(conn)}) catch {};
            return DatabaseError.DatabaseNotFound;
        }
    }
    pub fn startStatement(self: Connection) MemoryError!*Statement {
        const statement = mysql.mysql_stmt_init(self.connection);
        if (statement) |state| {
            return alloc: {
                const stmt = try self.allocator.create(Statement);
                stmt.* = Statement{
                    .connection = self.connection,
                    .stdio = self.stdio,
                    .statement = state,
                    .allocator = self.allocator,
                };
                break :alloc stmt;
            };
        } else {
            return error.OutOfMemory;
        }
    }
    pub fn deinit(self: *Connection) void {
        defer self.allocator.destroy(self);
        defer self.allocator.destroy(self.pointer);
        mysql.mysql_close(self.connection);
    }

    pub inline fn autoCommit(self: Connection, mode: bool) void {
        //No error on mysql_autocommit
        _ = mysql.mysql_autocommit(self.connection, mode);
    }
    pub inline fn commit(self: Connection) bool {
        return mysql.mysql_commit(self.connection);
    }
    pub inline fn rollback(self: Connection) void {
        _ = mysql.mysql_rollback(self.connection);
    }
};

const Statement = struct {
    connection: [*c]MYSQL_C,
    statement: [*c]MYSQL_STMT_C,
    stdio: Stdio,
    allocator: Allocator,

    pub fn preparedStatement(self: Statement, query: [:0]const u8) !PrepareStatement {
        const result = mysql.mysql_stmt_prepare(self.statement, query, @as(c_ulong, query.len));
        if (result != 0) {
            return PrepareStatement{};
        }
        self.stdio.stderr.print("error on preprared statement: {s}", mysql.mysql_stmt_error(self.statement));
        switch (result) {
            0 => {},
            mysql.CR_SERVER_LOST => ServerError.ServerLost,
            mysql.CR_COMMANDS_OUT_OF_SYNC => CommandsError.CommandsOutofSync,
            mysql.CR_SERVER_GONE_ERROR => ServerError.ServerGone,
            mysql.CR_UNKNOWN_ERROR => UnknownError.UnknownError,
            mysql.CR_OUT_OF_MEMORY => MemoryError.OutOfMemory,
            else => UnexpectedError.Unexpected,
        }
    }
    pub fn executeStatement(self: Statement, query: [:0]const u8, else_alloc: ?Allocator) (ServerError || CommandsError || MemoryError || UnknownError)!ResultSet {
        try self.execute(query);
        const result = mysql.mysql_store_result(self.connection);
        errdefer mysql.mysql_free_result(result);
        if (result == null) {
            self.stdio.stderr.print("Store result failed: {s}\n", .{mysql.mysql_error(self.connection)}) catch {};
            const err_no = mysql.mysql_errno(self.connection);
            return switch (err_no) {
                mysql.CR_COMMANDS_OUT_OF_SYNC => CommandsError.CommandsOutofSync,
                mysql.CR_SERVER_GONE_ERROR => ServerError.ServerGone,
                mysql.CR_SERVER_LOST => ServerError.ServerLost,
                mysql.CR_UNKNOWN_ERROR => UnknownError.UnknownError,
                mysql.CR_OUT_OF_MEMORY => MemoryError.OutOfMemory,
                else => unreachable,
            };
        }

        const alloc = if (else_alloc) |alloc_| alloc_ else self.allocator;
        return .{ .result = result, .allocator = alloc };
    }
    pub fn executeUpdate(self: Statement, query: [:0]const u8) !void {
        try self.execute(query);
    }
    pub fn insertTable(self: Statement) !void {
        const cat_colors = .{
            .{
                "Blue",
                .{ "Tigger", "Sammy" },
            },
            .{
                "Black",
                .{ "Oreo", "Biscuit" },
            },
        };

        const insert_color_stmt: *mysql.MYSQL_STMT = blk: {
            const stmt = mysql.mysql_stmt_init(self.connection);
            if (stmt == null) {
                return error.initStmt;
            }
            errdefer _ = mysql.mysql_stmt_close(stmt);

            const insert_color_query = "INSERT INTO cat_colors (name) values (?)";
            if (mysql.mysql_stmt_prepare(stmt, insert_color_query, insert_color_query.len) != 0) {
                const print = self.stdio.stderr.print;
                print("Prepare color stmt failed, msg:{s}\n", .{mysql.mysql_error(self.connection)});
                return error.prepareStmt;
            }

            break :blk stmt.?;
        };
        defer _ = mysql.mysql_stmt_close(insert_color_stmt);

        const insert_cat_stmt = blk: {
            const stmt = mysql.mysql_stmt_init(self.connection);
            if (stmt == null) {
                return error.initStmt;
            }
            errdefer _ = mysql.mysql_stmt_close(stmt);

            const insert_cat_query = "INSERT INTO cats (name, color_id) values (?, ?)";
            if (mysql.mysql_stmt_prepare(stmt, insert_cat_query, insert_cat_query.len) != 0) {
                const print = self.stdio.stderr.print;
                try print("Prepare cat stmt failed: {s}\n", .{mysql.mysql_error(self.connection)}) catch |err| switch (err) {
                    error.WriterError => {},
                };
                return error.prepareStmt;
            }

            break :blk stmt.?;
        };

        inline for (cat_colors) |row| {
            const color = row.@"0";
            const cat_names = row.@"1";

            var color_binds = [_]mysql.MYSQL_BIND{std.mem.zeroes(mysql.MYSQL_BIND)};
            color_binds[0].buffer_type = mysql.MYSQL_TYPE_STRING;
            color_binds[0].buffer_length = color.len;
            color_binds[0].is_null = 0;
            color_binds[0].buffer = @constCast(@ptrCast(color.ptr));

            if (mysql.mysql_stmt_bind_param(insert_color_stmt, &color_binds)) {
                const print = self.stdio.stderr.print;
                try print("Bind color param failed: {s}\n", .{mysql.mysql_error(self.connection)});
                return error.bindParamError;
            }
            if (mysql.mysql_stmt_execute(insert_color_stmt) != 0) {
                const print = self.stdio.stderr.print;
                print("Exec color stmt failed: {s}\n", .{mysql.mysql_error(self.connection)}) catch |err| switch (err) {
                    error.WriterError => {},
                };
                return error.execStmtError;
            }
            const last_id = mysql.mysql_stmt_insert_id(insert_color_stmt);
            _ = mysql.mysql_stmt_reset(insert_color_stmt);

            inline for (cat_names) |cat_name| {
                var cat_binds = [_]mysql.MYSQL_BIND{ std.mem.zeroes(mysql.MYSQL_BIND), std.mem.zeroes(mysql.MYSQL_BIND) };
                cat_binds[0].buffer_type = mysql.MYSQL_TYPE_STRING;
                cat_binds[0].buffer_length = cat_name.len;
                cat_binds[0].buffer = @constCast(@ptrCast(cat_name.ptr));

                cat_binds[1].buffer_type = mysql.MYSQL_TYPE_LONG;
                cat_binds[1].length = (@as(c_ulong, 1));
                cat_binds[1].buffer = @constCast(@ptrCast(&last_id));

                if (mysql.mysql_stmt_bind_param(insert_cat_stmt, &cat_binds)) {
                    const writer = self.stdio.stderr.writer();
                    try writer("Bind cat param failed: {s}\n", .{mysql.mysql_error(self.connection)});
                    return error.bindParamError;
                }
                if (mysql.mysql_stmt_execute(insert_cat_stmt) != 0) {
                    const writer = self.stdio.stderr.writer();
                    writer("Exec cat stmt failed: {s}\n", .{mysql.mysql_error(self.connection)});
                    return error.execStmtError;
                }

                _ = mysql.mysql_stmt_reset(insert_cat_stmt);
            }
        }
    }
    pub fn deinit(self: *Statement) void {
        defer self.allocator.destroy(self);
        if (!mysql.mysql_stmt_close(self.statement)) {
            return;
        }
        self.stdio.stderr.print("Error deinit statement: {s}\n", .{mysql.mysql_error(self.connection)}) catch {};
    }
    fn execute(self: Statement, query: [:0]const u8) !void {
        const case: c_int = mysql.mysql_real_query(self.connection, query, query.len);
        return switch (case) {
            //Success case
            0 => return,

            //Commands were executed in an improper order.
            mysql.CR_COMMANDS_OUT_OF_SYNC => CommandsError.CommandsOutofSync,

            //The MySQL server has gone away.
            mysql.CR_SERVER_GONE_ERROR => ServerError.ServerGone,

            //The connection to the server was lost during the query.
            mysql.CR_SERVER_LOST => ServerError.ServerLost,

            //An unknown error occurred.
            mysql.CR_UNKNOWN_ERROR => UnknownError.UnknownError,

            else => unreachable,
        };
    }
};
//Wraper for table
const ResultSet = struct {
    result: [*c]mysql.MYSQL_RES,
    allocator: Allocator,
    row: mysql.MYSQL_ROW = null,
    pub inline fn rowLen(self: ResultSet) usize {
        return mysql.mysql_num_fields(self.result);
    }
    //Return if row exist, the size of row
    //if none row next returns null
    pub fn nextRow(self: *ResultSet) !?[][:0]u8 {
        if (mysql.mysql_fetch_row(self.result)) |row| {
            self.row = row;
            const len = self.rowLen();
            const rowAlloc = try self.allocator.alloc([:0]u8, len);
            for (0..len) |index| {
                rowAlloc[index] = try std.fmt.allocPrintZ(self.allocator, "{s}", .{row[index]});
            }
            return rowAlloc;
        } else {
            return null;
        }
    }

    pub fn deinitRow(self: ResultSet, rowAlloc: [][:0]u8) void {
        defer self.allocator.free(rowAlloc);
        for (rowAlloc) |column| {
            self.allocator.free(column);
        }
    }
    pub fn indexRow(self: ResultSet, index: usize, buffer_size: ?usize) [:0]u8 {
        var buffer = [_]u8{0} ** (buffer_size orelse 65535);

        return std.fmt.bufPrintZ(&buffer, "{s}", .{self.row[index]}) catch {
            //return "" if error
            return std.fmt.bufPrintZ(&buffer, "", .{}) catch unreachable;
        };
    }
    pub inline fn indexAlloc(self: ResultSet, index: usize) ![:0]u8 {
        return try std.fmt.allocPrintZ(self.alloc, "{s}", .{self.row[index]});
    }
    pub fn deinit(self: *ResultSet) void {
        self.alloc.destroy(self);
        mysql.mysql_free_result(self.result);
    }
};
pub const PrepareStatement = struct {};
pub const SqlTypes = packed union {
    tiny: mysql.MYSQL_TYPE_TINY,
    short: mysql.MYSQL_TYPE_SHORT,
    long: mysql.MYSQL_TYPE_LONG,
    int24: mysql.MYSQL_TYPE_INT24,
    longlong: mysql.MYSQL_TYPE_LONGLONG,
    decimal: mysql.MYSQL_TYPE_DECIMAL,
    newdecimal: mysql.MYSQL_TYPE_NEWDECIMAL,
    float: mysql.MYSQL_TYPE_FLOAT,
    double: mysql.MYSQL_TYPE_DOUBLE,
    bit: mysql.MYSQL_TYPE_BIT,
    timestamp: mysql.MYSQL_TYPE_TIMESTAMP,
    date: mysql.MYSQL_TYPE_DATE,
    time: mysql.MYSQL_TYPE_TIME,
    datetime: mysql.MYSQL_TYPE_DATETIME,
    year: mysql.MYSQL_TYPE_YEAR,
    string: mysql.MYSQL_TYPE_STRING,
    var_string: mysql.MYSQL_TYPE_VAR_STRING,
    blob: mysql.MYSQL_TYPE_BLOB,
    set: mysql.MYSQL_TYPE_SET,
    @"enum": mysql.MYSQL_TYPE_ENUM,
    geometriy: mysql.MYSQL_TYPE_GEOMETRY,
    null: mysql.MYSQL_TYPE_NULL,
};
pub const ClientFlags = enum(c_ulong) {
    client_compress = mysql.CLIENT_COMPRESS,
    //provokes error
    //CAN_HANDLE_EXPIRED_PASSWORDS = c.CAN_HANDLE_EXPIRED_PASSWORDS,
    client_found_rows = mysql.CLIENT_FOUND_ROWS,

    client_ignore_sigpipe = mysql.CLIENT_IGNORE_SIGPIPE,

    client_ignore_space = mysql.CLIENT_IGNORE_SPACE,
    client_interactive = mysql.CLIENT_INTERACTIVE,
    client_local_files = mysql.CLIENT_LOCAL_FILES,
    client_multi_results = mysql.CLIENT_MULTI_RESULTS,
    client_multi_statements = mysql.CLIENT_MULTI_STATEMENTS,
    client_no_schema = mysql.CLIENT_NO_SCHEMA,

    //unused
    client_odbc = mysql.CLIENT_ODBC,
    client_optional_resultset_metadata = mysql.CLIENT_OPTIONAL_RESULTSET_METADATA,
    client_ssl = mysql.CLIENT_SSL,
    client_remember_options = mysql.CLIENT_REMEMBER_OPTIONS,

    pub fn bitMask(flags: []const ClientFlags) c_ulong {
        return blk: {
            var bit_used: c_ulong = 0;
            for (flags) |bit| {
                const bit_usize: c_ulong = @intFromEnum(bit);
                bit_used |= bit_usize;
            }
            break :blk bit_used;
        };
    }
};
const testing = std.testing;
test "deallocation" {
    const alloc = std.testing.allocator;
    const conn_error = Connection.init(.{ .database = "tetdb" }, .{}, alloc);
    try testing.expectError(error.DatabaseNotFound, conn_error);
    const conn =
        Connection.init(
        .{ .database = "testdb" },
        .{
            .auto_commit = false,
            .flags = &.{.client_multi_statements},
        },
        alloc,
    ) catch unreachable;
    defer conn.deinit();
    const statement = try conn.startStatement();
    defer statement.deinit();
    const state = "SELECT * FROM cats";
    var x = statement.executeStatement(state, null) catch unreachable;
    while (try x.nextRow()) |allocated| {
        defer x.deinitRow(allocated);
        std.debug.print("{s}\n", .{allocated});
    }
}

test "init" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    const alloc = gpa.allocator();
    //const default = [_]ClientFlags{ .client_compress, .client_multi_statements };

    var conn = try Connection.init(.{ .database = "testdb" }, .{}, alloc);

    conn.deinit();
}
