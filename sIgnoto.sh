#!/bin/bash
# Identifica segmento de trabajo, busca equipos usando arp-scan e identifica posible S.O. segun TTL
# Realizado por Moises Beltran D.

#Limpiar Pantalla
clear

#Definicion de Funciones
#----------------------------------------------------------------------------------------------------------------------------------------------
    verIPencontrada()
    {   
        echo "|¯¯¯¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|"
        echo "| ID |        IP       |"
        echo "|ˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
        echo "|    |                 |"
        for i in ${!hostEncontrado[@]}; do
            printf "|"
            printf "%-4s" "$i"
            printf "%-18s" "| ${hostEncontrado[$i]}"
            printf "%-1s \n" "|"
        done
        echo "|ˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    crearArchivoHost()
    {
        sudo arp-scan -l --format='${ip}' | grep ^$segmento | sort > host.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    verIPsegmento()
    {
        #echo $ipSegmento
        #echo "-------------------------"    
        #De la linea separo e identifico 3 octetos
        miIP=$(echo $ipSegmento | cut -d " " -f8 )
        #echo $miIP
        oct1=$(echo $ipSegmento | cut -d " " -f8 | cut -d "." -f1)
        #echo $oct1
        oct2=$(echo $ipSegmento | cut -d " " -f8 | cut -d "." -f2)
        #echo $oct2
        oct3=$(echo $ipSegmento | cut -d " " -f8 | cut -d "." -f3)
        #echo $oct3
        #Con los octetos realizo armado de segmento
        segmento=$oct1.$oct2.$oct3
        #echo $segmento
        echo "IP local es                         : $miIP"
        echo "El segmento en el que se buscara es : $segmento.x/24"
        echo " "
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    leerOpcion()   
    {   
        clear
        verIPsegmento
        verIPencontrada
        echo " "
        read -p "Ingresa el ID de la IP listada: " idMenu
        echo " "
        validarOpcion
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    validarOpcion()
    {
        while ! [[ "$idMenu" =~ ^[0-9]+$ ]] || ! [ "$idMenu" -ge 0 ] || ! [ "$idMenu" -lt ${#hostEncontrado[@]} ]
        do
            echo -e "\e[0;31m La opcion ingresada no es valida...\e[0m "
            sleep 3
            leerOpcion
        done
    }
#----------------------------------------------------------------------------------------------------------------------------------------------    
    leerArchivoHost()
    {
        #Leo archivo linea a linea para guardar en arreglo que usare posteriormente
        while IFS='' read -r linea || [[ -n "$linea" ]]; do
            #printf ">%s<\n" "$linea"
            hostEncontrado+=("$linea")
        done < host.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    buscaTTL()
    {
        ipTTL=$(ping -c 1 ${hostEncontrado[$idMenu]} | grep -oE "ttl=[0-9]{2,3}" | sed s/"ttl=//g")
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    verSOsegunTTL()
    {
        buscaTTL
        if [ "$ipTTL" ]
            then
                case $ipTTL in
                        64)
                            posibleSistema="Unix/Linux"
                        ;;
                        128)
                            posibleSistema="Windows"
                        ;;
                        254)
                            posibleSistema="Solaris/AIX"
                        ;;
                        255)
                            posibleSistema="BSD/OS"
                        ;;
                        *)
                            posibleSistema="Sin informacion"
                        ;;
                esac
                echo    "|¯¯¯¯¯¯¯¯¯¯¯¯¯|¯¯¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|"
                echo    "|       IP    |TTL|  POSIBLE SISTEMA  |"
                echo    "|ˍˍˍˍˍˍˍˍˍˍˍˍˍ|ˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
                printf    "|"
                printf  '\e[1;34m%-13s\e[0m' "${hostEncontrado[$idMenu]}"
                printf    "|"
                printf  '\e[1;34m%-3s\e[0m' "$ipTTL"
                printf    "|"
                printf  '\e[1;34m%-19s\e[0m' "$posibleSistema"
                printf  "%-1s \n" "|"
                echo    "|ˍˍˍˍˍˍˍˍˍˍˍˍˍ|ˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
                
            else
                echo "Sin TTL para informar"
        fi
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    crearArchivoPuerto()
    {
        echo " "
        ruta=$(pwd)
        echo -e "Buscando puertos abiertos... (\e[0;33mEsto puede tardar un poco...\e[0m) " #en IP ${hostEncontrado[$idMenu]}
        sudo nmap -vvv -p- -T4 -sS ${hostEncontrado[$idMenu]}  | grep ^"Discovered open port" | cut -d " " -f4 | cut -d "/" -f1 | sort > puerto_${hostEncontrado[$idMenu]}.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    leerArchivoPuerto()
    {
        #Leo archivo linea a linea para guardar en arreglo que usare posteriormente
        while IFS='' read -r linea || [[ -n "$linea" ]]; do
            #printf ">%s<\n" "$linea"
            puertoEncontrado+=("$linea")
        done < puerto_${hostEncontrado[$idMenu]}.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    verPuerto()
    {
                printf  "%-93s \n"  "|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|"
                printf  "%-29s"     "|          Se han encontrado "
                printf '\e[1;34m%-5s\e[0m'  "${#puertoEncontrado[@]}"
                printf  "%-58s"     " puerto(s) abiertos        "
                printf  "%-1s \n"   "|"
                printf  "%-93s \n"  "|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
                printf  "%-1s"      " "
                printf '\e[1;34m%-19s\e[0m'  "${puertoEncontrado[*]}"
                printf  "%-1s \n" " "
                printf  "%-93s"     "|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"

        
        
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    crearArchivoServicio()
    {
        echo " "
        ruta=$(pwd)
        sudo nmap $lineaPuerto -sV -T4 ${hostEncontrado[$idMenu]} | grep "open" | sort > servicio_${hostEncontrado[$idMenu]}.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    leerArchivoServicio()
    {
        #Leo archivo linea a linea para guardar en arreglo que usare posteriormente
        while IFS='' read -r linea || [[ -n "$linea" ]]; do
            #printf ">%s<\n" "$linea"
            servicioEncontrado+=("$linea")
        done < servicio_${hostEncontrado[$idMenu]}.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    verServicioEncontrado()
    {   
        printf  "%-127s \n"  "|¯¯¯¯¯¯¯¯¯¯¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯"
        printf  "%-127s \n"  "|  PUERTO   |        SERVICIO       |               VERSION                                                                    "
        printf  "%-127s \n"  "|ˍˍˍˍˍˍˍˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ"
                
        for i in ${!servicioEncontrado[@]}; 
        do
            sPuerto=$(echo ${servicioEncontrado[$i]} | cut -d " " -f1)
            sServicio=$(echo ${servicioEncontrado[$i]} | cut -d " " -f3)
            sVersion=$(echo ${servicioEncontrado[$i]} | cut -d " " -f4-)
        
            printf "%-12s" "| $sPuerto"
            printf "%-24s" "| $sServicio"
            printf "%-48s \n" "| $sVersion"
        done
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    buscarServicio()
    {
        if [ "$puertoEncontrado" ]
            then
                echo " "
                echo -e "Identificando servicios (\e[0;33mEsto puede tardar un poco...\e[0m)"
                inicio=0
                let fin=${#puertoEncontrado[@]}-1 

                for i in ${!puertoEncontrado[@]}; 
                    do
                        if [ $i -eq $inicio ]
                            then
                                lineaPuerto="-p${puertoEncontrado[$i]}"
                        else
                            if [ $i -eq $fin ]
                                then 
                                    lineaPuerto="$lineaPuerto,${puertoEncontrado[$i]}"
                            else
                                lineaPuerto="$lineaPuerto,${puertoEncontrado[$i]}"
                            fi
                        fi
                done
                crearArchivoServicio
            else
                echo "No hay puertos para escanear"
                        
        fi
    }

#----------------------------------------------------------------------------------------------------------------------------------------------
    generarArchivoReport()
    {
        read -p "Desea crear archivo resumen S/N (Esto tarda...): " crearResumen

        if [ "$crearResumen" ]
            then
                if [ $crearResumen == "S" ]
                    then
                        verSOsegunTTL > Reporte_${hostEncontrado[$idMenu]}.txt
                        verPuerto >> Reporte_${hostEncontrado[$idMenu]}.txt
                        verServicioEncontrado >> Reporte_${hostEncontrado[$idMenu]}.txt
                fi
        fi
    }   
#----------------------------------------------------------------------------------------------------------------------------------------------
#**********************************************************************************************************************************************
    #Uso ifconfig y capturo linea de "Interface" para sacar info  de IP y segmento de esta.
    ipSegmento=$(sudo arp-scan -l -M 1 | grep "Interface")
    #Extraigo y muestro la IP y el Segmento
    verIPsegmento
    #Creo archivo con IP de equipos que responden a archivo host.txt
    crearArchivoHost
    #Realizo lectura de archivo y envio IP a un arreglo 
    leerArchivoHost
    #Muestro IP encontradas desde arreglo 
    verIPencontrada
    #Segun IP encontradas pido al usuario seleccionar una para trabajar con ella
    leerOpcion
    #Muestro sistema operativo segun TTL identificado
    verSOsegunTTL
    #Busca puertos abiertos en equipo seleccionado y guarda en archivo
    crearArchivoPuerto
    #Realizo lectura de archivo y envio IP a un arreglo 
    leerArchivoPuerto
    #Mostrar puertos encontrados
    verPuerto
    #Buscar servicios para puertos y guarda en archivo
    buscarServicio
    #Realizo lectura de archivo y envio servicios a un arreglo 
    leerArchivoServicio
    #Muestro servicios encontrados
    verServicioEncontrado
    generarArchivoReport
    #**********************************************************************************************************************************************