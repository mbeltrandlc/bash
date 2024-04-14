#!/bin/bash
# Identifica segmento de trabajo, busca equipos usando ping e identifica posible S.O. segun TTL
# Realizado por Moises Beltran D.

#Limpiar Pantalla
clear

#Definicion de Funciones
#----------------------------------------------------------------------------------------------------------------------------------------------
    verIPencontrada()
    {   
        printf "%-24s \n" "|¯¯¯¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|"
        printf "%-24s \n" "| ID |        IP       |"
        printf "%-24s \n" "|ˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
        printf "%-24s \n" "|    |                 |"
        for i in ${!hostEncontrado[@]}; do
            printf "|"
            printf "%-4s" "$i"
            printf "%-18s" "| ${hostEncontrado[$i]}"
            printf "%-1s \n" "|"
        done
        printf "%-24s \n" "|ˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    crearArchivoHost()
    {
        sudo arp-scan -l --format='${ip}' | grep ^$segmento | sort > "00"_host.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    verIPsegmento()
    {
        #De la linea separo e identifico 3 octetos
        miIP=$(echo $ipSegmento | cut -d " " -f8 )
        oct1=$(echo $ipSegmento | cut -d " " -f8 | cut -d "." -f1)
        oct2=$(echo $ipSegmento | cut -d " " -f8 | cut -d "." -f2)
        oct3=$(echo $ipSegmento | cut -d " " -f8 | cut -d "." -f3)
        
        #Con los octetos realizo armado de segmento
        segmento=$oct1.$oct2.$oct3
        
        printf "%-40s   " "IP local                            : "
        printf "%-15s \n" "$miIP"
        printf "%-40s   " "El segmento en el que se buscara es : "
        printf "%-15s \n \n" "$segmento.x/24"
        
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    leerOpcion()   
    {   
        clear
        verIPsegmento
        verIPencontrada
        printf "\n"
        read -p "Ingresa el ID de la IP listada: " idMenu
        printf "\n"
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
        done < "00"_host.txt
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
                printf "%-41s \n" "|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|¯¯¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|"
                printf "%-41s \n" "|       IP      |TTL|  POSIBLE SISTEMA  |"
                printf "%-41s \n" "|---------------|---|-------------------|"
                printf            "|"
                printf  "%-13s" "${hostEncontrado[$idMenu]}"
                #printf  '\e[1;34m%-13s\e[0m' "${hostEncontrado[$idMenu]}"
                printf                            "|"
                printf  "%-3s" "$ipTTL"
                #printf  '\e[1;34m%-3s\e[0m' "$ipTTL"
                printf                                "|"
                printf  "%-19s" " $posibleSistema"
                #printf  '\e[1;34m%-19s\e[0m' " $posibleSistema"
                printf "%-1s \n"                                          "|"
                printf "%-41s \n" "|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|ˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
                
            else
                printf "%-21s \n" "Sin TTL para informar"
        fi
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    crearArchivoPuerto()
    {
        echo " "
        ruta=$(pwd)
        echo -e "Buscando puertos abiertos... (\e[0;33mEsto puede tardar un poco...\e[0m) " #en IP ${hostEncontrado[$idMenu]}
        sudo nmap -vvv -p- -T4 -sS ${hostEncontrado[$idMenu]}  | grep ^"Discovered open port" | cut -d " " -f4 | cut -d "/" -f1 | sort > "01"_puerto_${hostEncontrado[$idMenu]}.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    leerArchivoPuerto()
    {
        #Leo archivo linea a linea para guardar en arreglo que usare posteriormente
        while IFS='' read -r linea || [[ -n "$linea" ]]; do
            #printf ">%s<\n" "$linea"
            puertoEncontrado+=("$linea")
        done < "01"_puerto_${hostEncontrado[$idMenu]}.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    verPuerto()
    {
                printf  "%-93s \n"  "|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|"
                printf  "%-29s"     "|          Se han encontrado "
                printf  "%-5s"      "${#puertoEncontrado[@]}"
                #printf '\e[1;34m%-5s\e[0m'  "${#puertoEncontrado[@]}"
                printf  "%-58s"     " puerto(s) abiertos        "
                printf  "%-1s \n"   "|"
                printf  "%-93s \n"  "|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"
                printf  "%-1s"      " "
                printf '%-19s'  "${puertoEncontrado[*]}"
                #printf '\e[1;34m%-19s\e[0m'  "${puertoEncontrado[*]}"
                printf  "%-1s \n" " "
                printf  "%-93s \n"  "|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|"

        
        
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    crearArchivoServicio()
    {
        sudo nmap $lineaPuerto -sV -T4 ${hostEncontrado[$idMenu]} | grep "open" | sort > "02"_servicio_${hostEncontrado[$idMenu]}.txt
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    leerArchivoServicio()
    {
        #Leo archivo linea a linea para guardar en arreglo que usare posteriormente
        while IFS='' read -r linea || [[ -n "$linea" ]]; do
            #printf ">%s<\n" "$linea"
            servicioEncontrado+=("$linea")
        done < "02"_servicio_${hostEncontrado[$idMenu]}.txt
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
        printf  "%-127s \n"  "|ˍˍˍˍˍˍˍˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ|ˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍˍ"
    }
#----------------------------------------------------------------------------------------------------------------------------------------------
    buscarServicio()
    {
        if [ "$puertoEncontrado" ]
            then
                printf "\n"
                echo -e "Identificando servicios...   (\e[0;33mEsto puede tardar un poco...\e[0m)"
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
        printf "\n"
        read -p "Desea crear archivo resumen S/N : " crearResumen

        if [ "$crearResumen" ]
            then
                if [ $crearResumen == "S" ]
                    then
                        verSOsegunTTL > "03"_reporte_${hostEncontrado[$idMenu]}.txt
                        printf "\n" >> "03"_reporte_${hostEncontrado[$idMenu]}.txt
                        verPuerto >> "03"_reporte_${hostEncontrado[$idMenu]}.txt
                        printf "\n" >> "03"_reporte_${hostEncontrado[$idMenu]}.txt
                        verServicioEncontrado >> "03"_reporte_${hostEncontrado[$idMenu]}.txt
                fi
                printf "Archivo reporte generado : $(pwd)/03_reporte_${hostEncontrado[$idMenu]}.txt"
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