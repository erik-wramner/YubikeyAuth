<html>
<head>
<title>Yubikey example - Login</title>
</head>
<body>
	<h1>Login</h1>
	<p>
	<form action="j_security_check" method="POST"
		onsubmit="this.j_password.value = this.password.value + '|' + this.otp.value; return true;">
		<input type="hidden" name="j_password" />
		<table>
			<tr>
				<td><label for="j_username">E-mail:</label></td>
				<td><input name="j_username" type="text"></td>
			</tr>
			<tr>
				<td><label for="password">Password:</label></td>
				<td><input name="password" type="password"></td>
			</tr>
			<tr>
				<td><label for="otp">OTP:</label></td>
				<td><input name="otp" type="password"></td>
			</tr>
			<tr>
				<td colspan="2"><input type="submit" value="Login"></td>
			</tr>
			<%
			  if (request.getParameter("loginFailed") != null) {
			%>
			<tr>
				<td colspan="2">Login failed, please try again.</td>
			</tr>
			<%
			  }
			%>
		</table>
	</form>
</body>
</html>