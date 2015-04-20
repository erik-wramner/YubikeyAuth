<html>
<head>
<title>Yubikey example - Login</title>
</head>
<body>
	<h1>Login</h1>
	<p>
	<form action="login.jsp" method="POST">
		<table>
			<tr>
				<td><label for="username">E-mail:</label></td>
				<td><input name="username" type="text"></td>
			</tr>
			<tr>
				<td><label for="password">Password:</label></td>
				<td><input name="password" type="password"></td>
			</tr>
			<tr>
				<td><label for="otp">OTP:</label></td>
				<td><input name="otp" type="password"></td>
			</tr>
			<%
			  if (request.getAttribute("shiroLoginFailure") != null) {
			%>
			<tr>
				<td colspan="2">Login failed, please try again.</td>
			</tr>
			<%
			  }
			%>
			<tr>
				<td colspan="2"><input type="submit" value="Login"></td>
			</tr>
		</table>
	</form>
</body>
</html>