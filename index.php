<?php 

if(isset($_GET['get']) && $_GET['get'] == "base")
    echo file_get_contents("fm_base.php");
elseif(isset($_GET['get']) && $_GET['get'] == 1)
    echo file_get_contents("fm_new.php");
else
    echo "2.4.1";
