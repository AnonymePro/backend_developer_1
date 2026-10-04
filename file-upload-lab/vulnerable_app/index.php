<!DOCTYPE html>
<html>
<head><title>VulnShop - Profile Picture Upload</title></head>
<body>
    <h1>VulnShop: Upload your profile picture</h1>
    <p><strong>Lab target — intentionally vulnerable. Do not expose this server to the internet.</strong></p>
    <form action="upload.php" method="post" enctype="multipart/form-data">
        <input type="file" name="avatar">
        <input type="submit" value="Upload">
    </form>

    <h2>Uploaded files</h2>
    <ul>
    <?php
        foreach (glob("uploads/*") as $f) {
            $name = htmlspecialchars(basename($f));
            echo "<li><a href=\"uploads/$name\">$name</a></li>";
        }
    ?>
    </ul>
</body>
</html>
