name := """play-auth"""
organization := "example"

scalaVersion := "2.13.0"
crossScalaVersions := List("2.13.0", "2.12.8", "2.11.12")
scalacOptions ++= Seq("-unchecked", "-deprecation")

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

libraryDependencies ++= Seq(
  guice,
  "javax.xml.bind" % "jaxb-api" % "2.3.1",
  "org.mindrot" % "jbcrypt" % "0.4",
  "org.scalatestplus.play" %% "scalatestplus-play" % "5.0.0" % Test
)
